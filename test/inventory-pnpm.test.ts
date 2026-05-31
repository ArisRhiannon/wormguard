// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanNodeModules } from "../src/inventory";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "wg-inv-"));
}

function pkg(dir: string, name: string, scripts: Record<string, string> = {}): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", scripts }));
}

describe("inventory walker (multi-layout)", () => {
  test("npm flat layout: top-level + scoped", () => {
    const root = tmp();
    pkg(join(root, "node_modules", "lodash"), "lodash");
    pkg(join(root, "node_modules", "@scope", "pkg"), "@scope/pkg");
    const r = scanNodeModules(root);
    const names = r.map((p) => p.name).sort();
    expect(names).toContain("lodash");
    expect(names).toContain("@scope/pkg");
  });

  test("npm v2-style nested node_modules", () => {
    const root = tmp();
    pkg(join(root, "node_modules", "outer"), "outer");
    pkg(join(root, "node_modules", "outer", "node_modules", "inner"), "inner", {
      postinstall: "node ./build.js",
    });
    const r = scanNodeModules(root);
    expect(r.some((p) => p.name === "inner" && p.layout === "nested")).toBe(true);
  });

  test("pnpm .pnpm store layout: real packages under .pnpm/<id>/node_modules", () => {
    const root = tmp();
    // Real package in the store.
    const realDir = join(root, "node_modules", ".pnpm", "esbuild@0.20.0", "node_modules", "esbuild");
    pkg(realDir, "esbuild", { postinstall: "node install.js" });
    // Symlinked surface entry (pnpm-link).
    const linkParent = join(root, "node_modules");
    mkdirSync(linkParent, { recursive: true });
    symlinkSync(realDir, join(linkParent, "esbuild"), "dir");
    const r = scanNodeModules(root);
    const esbuilds = r.filter((p) => p.name === "esbuild");
    // Both surfaces resolve to the same real path; we should report once.
    expect(esbuilds.length).toBe(1);
    expect(esbuilds[0]?.scripts.postinstall).toBe("node install.js");
  });

  test("pnpm .pnpm store: scoped packages under .pnpm/<id>/node_modules/@scope/<name>", () => {
    const root = tmp();
    pkg(
      join(root, "node_modules", ".pnpm", "@scope+pkg@1.0.0", "node_modules", "@scope", "pkg"),
      "@scope/pkg",
    );
    const r = scanNodeModules(root);
    expect(r.some((p) => p.name === "@scope/pkg")).toBe(true);
  });

  test("missing node_modules → []", () => {
    expect(scanNodeModules(tmp())).toEqual([]);
  });

  test(".bin and other dotted entries are skipped", () => {
    const root = tmp();
    mkdirSync(join(root, "node_modules", ".bin"), { recursive: true });
    writeFileSync(
      join(root, "node_modules", ".bin", "x"),
      `{"name":"should-not-be-scanned","version":"1"}`,
    );
    pkg(join(root, "node_modules", "real"), "real");
    const r = scanNodeModules(root);
    expect(r.map((p) => p.name)).toEqual(["real"]);
  });

  test("malformed package.json is skipped silently", () => {
    const root = tmp();
    mkdirSync(join(root, "node_modules", "broken"), { recursive: true });
    writeFileSync(join(root, "node_modules", "broken", "package.json"), "not json");
    pkg(join(root, "node_modules", "good"), "good");
    const r = scanNodeModules(root);
    expect(r.some((p) => p.name === "good")).toBe(true);
    expect(r.some((p) => p.name === "broken")).toBe(false);
  });
});
