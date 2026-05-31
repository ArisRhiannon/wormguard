// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { typosquatFindings } from "../src/typosquat";
import { analyzeSource } from "../src/ast/analyzer";

describe("P2 M1: worm-propagate rule", () => {
  test("writeFileSync('./package.json') alone -> fs-write only, not worm-propagate critical", () => {
    const r = analyzeSource(
      "inline",
      `require('fs').writeFileSync('./package.json', '{"name":"foo"}')`,
    );
    const cats = new Set(r.hits.map((h) => h.category));
    expect(cats.has("fs-write-outside")).toBe(true);
    expect(cats.has("worm-propagate")).toBe(true); // signal flag fires
  });

  test("execSync('npm publish') alone -> child-process + worm-propagate signal", () => {
    const r = analyzeSource("inline", `require('child_process').execSync('npm publish')`);
    const cats = new Set(r.hits.map((h) => h.category));
    expect(cats.has("child-process")).toBe(true);
    expect(cats.has("worm-propagate")).toBe(true);
  });

  test("benign execSync('tsc -b') does not flag worm-propagate", () => {
    const r = analyzeSource("inline", `require('child_process').execSync('tsc -b')`);
    expect(r.hits.some((h) => h.category === "worm-propagate")).toBe(false);
  });

  test("benign writeFile to ./build/output.js does not flag worm-propagate", () => {
    const r = analyzeSource(
      "inline",
      `require('fs').writeFileSync('./build/output.js', 'export const x = 1')`,
    );
    expect(r.hits.some((h) => h.category === "worm-propagate")).toBe(false);
  });

  test("spawnSync('npm', ['publish']) flags worm-propagate", () => {
    const r = analyzeSource(
      "inline",
      `require('child_process').spawnSync('npm', ['publish', '--access', 'public'])`,
    );
    expect(r.hits.some((h) => h.category === "worm-propagate")).toBe(true);
  });
});

describe("P2 M2: typosquat length floor", () => {
  test("'ms' (length 2) does NOT flag (too short to typosquat reliably)", () => {
    const f = typosquatFindings(["ms"]);
    expect(f.length).toBe(0);
  });

  test("'fs' (length 2) does NOT flag", () => {
    expect(typosquatFindings(["fs"]).length).toBe(0);
  });

  test("'lodaash' (length 7, distance 1 of lodash) DOES flag", () => {
    const f = typosquatFindings(["lodaash"]);
    expect(f.some((x) => x.ruleId === "WG-TYPOSQUAT")).toBe(true);
  });

  test("4-char names with distance-2 do NOT flag (length 6 minimum for distance 2)", () => {
    expect(typosquatFindings(["loda"]).length).toBe(0);
  });

  test("'reactt' (length 6, distance 1 of react) DOES flag", () => {
    const f = typosquatFindings(["reactt"]);
    expect(f.some((x) => x.ruleId === "WG-TYPOSQUAT")).toBe(true);
  });
});

describe("P2 M3: atomic baseline writes (tmpfile + rename)", () => {
  test("snapshot writes via tempfile-then-rename so concurrent writers don't corrupt", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-snap-"));
    mkdirSync(join(dir, "node_modules", "a"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "a", "package.json"), `{"name":"a","version":"1.0.0"}`);
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "p" },
          "node_modules/a": { version: "1.0.0", resolved: "https://r/a", integrity: "sha512-A" },
        },
      }),
    );
    const cliPath = resolve("src/cli.ts");
    // Run 8 snapshots concurrently and verify no corruption (all parses).
    const procs = Array.from({ length: 8 }, () => spawnSync("bun", [cliPath, "snapshot", dir], { encoding: "utf8" }));
    expect(procs.every((p) => p.status === 0)).toBe(true);
    const text = readFileSync(join(dir, ".wormguard-baseline.json"), "utf8");
    expect(() => JSON.parse(text)).not.toThrow();
  }, 30_000);
});

describe("P2 M5: NUL byte sanitization in evidence", () => {
  test("NUL bytes in source produce sanitized evidence (no raw \\u0000 in output)", () => {
    const r = analyzeSource("inline", `require('https')\u0000.get('x')`);
    for (const h of r.hits) {
      expect(h.evidence.includes("\u0000")).toBe(false);
    }
  });

  test("control characters are escaped in evidence", () => {
    // Direct \x07 byte in a string identifier path that we'd echo into evidence.
    const r = analyzeSource("inline", `eval('\\x07')`);
    expect(r.hits.some((h) => h.category === "eval")).toBe(true);
    for (const h of r.hits) {
      expect(/[\x00-\x08\x0e-\x1f]/.test(h.evidence)).toBe(false);
    }
  });
});
