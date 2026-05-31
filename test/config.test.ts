import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/index";

const tmp = mkdtempSync(join(tmpdir(), "wg-cfg-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("loadConfig", () => {
  test("missing config → {}", () => {
    expect(loadConfig(join(tmp, "none"))).toEqual({});
  });
  test("malformed JSON → {} (no throw)", () => {
    writeFileSync(join(tmp, ".wormguard.json"), "{ not json");
    expect(loadConfig(tmp)).toEqual({});
  });
  test("valid config is parsed", () => {
    writeFileSync(join(tmp, ".wormguard.json"), JSON.stringify({ failSeverity: "critical", ignoreRules: ["WG-ENV-ENUM"] }));
    expect(loadConfig(tmp).failSeverity).toBe("critical");
  });
});
