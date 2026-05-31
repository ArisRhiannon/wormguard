// SPDX-License-Identifier: MIT
import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/config";

const tmp = mkdtempSync(join(tmpdir(), "wg-cfg-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("loadConfig — trust model", () => {
  test("missing config → defaults, source=default", () => {
    const empty = mkdtempSync(join(tmpdir(), "wg-cfg-empty-"));
    const r = loadConfig(empty, { ignoreEnv: true });
    expect(r.config).toEqual({});
    expect(r.source).toBe("default");
    expect(r.findings.length).toBe(0);
  });

  test("in-repo .wormguard.json is IGNORED by default and emits a low finding", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-inrepo-"));
    writeFileSync(join(dir, ".wormguard.json"), JSON.stringify({ failSeverity: "low", ignoreRules: ["WG-SHELL-PIPE"] }));
    const r = loadConfig(dir, { ignoreEnv: true });
    expect(r.source).toBe("in-repo-ignored");
    expect(r.config).toEqual({}); // attacker config NOT applied
    expect(r.findings.length).toBe(1);
    expect(r.findings[0]?.ruleId).toBe("WG-CONFIG-IN-REPO-IGNORED");
    expect(r.findings[0]?.severity).toBe("low");
  });

  test("--trust-repo-config explicitly opts into reading the in-repo file", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-trusted-"));
    writeFileSync(join(dir, ".wormguard.json"), JSON.stringify({ failSeverity: "critical" }));
    const r = loadConfig(dir, { ignoreEnv: true, trustRepoConfig: true });
    expect(r.source).toBe("in-repo-trusted");
    expect(r.config.failSeverity).toBe("critical");
  });

  test("--config FILE takes precedence over in-repo and env", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-cli-"));
    const ext = mkdtempSync(join(tmpdir(), "wg-cfg-ext-"));
    writeFileSync(join(dir, ".wormguard.json"), JSON.stringify({ failSeverity: "low" }));
    writeFileSync(join(ext, "ci.json"), JSON.stringify({ failSeverity: "critical", ignoreRules: ["X"] }));
    const r = loadConfig(dir, { configPath: join(ext, "ci.json"), ignoreEnv: true });
    expect(r.source).toBe("cli-flag");
    expect(r.config.failSeverity).toBe("critical");
    expect(r.config.ignoreRules).toEqual(["X"]);
  });

  test("--config relative path resolves against scan dir", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-rel-"));
    writeFileSync(join(dir, "policy.json"), JSON.stringify({ failSeverity: "critical" }));
    const r = loadConfig(dir, { configPath: "policy.json", ignoreEnv: true });
    expect(r.source).toBe("cli-flag");
    expect(r.config.failSeverity).toBe("critical");
  });

  test("--config FILE missing emits WG-CONFIG-MISSING (medium)", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-missing-"));
    const r = loadConfig(dir, { configPath: "/nonexistent/path.json", ignoreEnv: true });
    expect(r.source).toBe("default");
    expect(r.findings.some((f) => f.ruleId === "WG-CONFIG-MISSING" && f.severity === "medium")).toBe(true);
  });

  test("WORMGUARD_CONFIG env var loads when no --config given", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-env-"));
    const ext = mkdtempSync(join(tmpdir(), "wg-cfg-env-ext-"));
    const cfgFile = join(ext, "env-cfg.json");
    writeFileSync(cfgFile, JSON.stringify({ failSeverity: "critical", ignoreRules: ["FROM-ENV"] }));
    const prev = process.env.WORMGUARD_CONFIG;
    process.env.WORMGUARD_CONFIG = cfgFile;
    try {
      const r = loadConfig(dir);
      expect(r.source).toBe("environment");
      expect(r.config.failSeverity).toBe("critical");
      expect(r.config.ignoreRules).toEqual(["FROM-ENV"]);
    } finally {
      if (prev) process.env.WORMGUARD_CONFIG = prev;
      else delete process.env.WORMGUARD_CONFIG;
    }
  });

  test("malformed in-repo JSON with --trust-repo-config falls back to defaults (no throw)", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-bad-"));
    writeFileSync(join(dir, ".wormguard.json"), "{ not json");
    const r = loadConfig(dir, { ignoreEnv: true, trustRepoConfig: true });
    expect(r.config).toEqual({});
  });

  test("attacker config in repo cannot disable critical findings under default trust model", () => {
    const dir = mkdtempSync(join(tmpdir(), "wg-cfg-attack-"));
    writeFileSync(
      join(dir, ".wormguard.json"),
      JSON.stringify({
        failSeverity: "low",
        ignoreRules: ["WG-SHELL-PIPE", "WG-AST-NETWORK-BUILTIN"],
        scriptFingerprints: { "any-pkg": ["abc"] },
      }),
    );
    const r = loadConfig(dir, { ignoreEnv: true });
    // None of the attacker fields land in the effective config.
    expect(r.config.failSeverity).toBeUndefined();
    expect(r.config.ignoreRules).toBeUndefined();
    expect(r.config.scriptFingerprints).toBeUndefined();
  });
});
