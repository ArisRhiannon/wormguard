import { test, expect, describe } from "bun:test";
import { snapshot, serializeBaseline, parseBaseline, diff, WormguardError, type PackageRecord } from "../src/index";

const rec = (name: string, p: Partial<PackageRecord> = {}): PackageRecord => ({
  name, version: "1.0.0",
  resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
  integrity: "sha512-A", registryHost: "registry.npmjs.org",
  hasInstallScript: false, dev: false, packageManager: "npm", ...p,
});

const base = () => snapshot([rec("a"), rec("b")]);
const has = (fs: { ruleId: string; pkg: string }[], pkg: string, id: string) => fs.some((f) => f.pkg === pkg && f.ruleId === id);

describe("AC3.1 snapshot round-trip", () => {
  test("serialize∘parse∘serialize is stable", () => {
    const s = serializeBaseline(base());
    expect(serializeBaseline(parseBaseline(s))).toBe(s);
  });
  test("invalid baseline throws", () => {
    expect(() => parseBaseline("{")).toThrow(WormguardError);
    expect(() => parseBaseline(JSON.stringify({ version: 9 }))).toThrow(WormguardError);
  });
});

describe("AC3.2/3.3/3.4/3.5 diff", () => {
  test("added / removed / version change", () => {
    const f = diff(base(), [rec("a"), rec("c"), rec("b", { version: "2.0.0" })]);
    expect(has(f, "c", "WG-DIFF-ADDED")).toBe(true);
    expect(has(f, "b", "WG-DIFF-VERSION")).toBe(true);
    const f2 = diff(base(), [rec("a")]); // b removed
    expect(has(f2, "b", "WG-DIFF-REMOVED")).toBe(true);
  });
  test("AC3.3 gained install script ⇒ high worm-signature finding", () => {
    const f = diff(base(), [rec("a"), rec("b", { hasInstallScript: true })]);
    const hit = f.find((x) => x.ruleId === "WG-DIFF-NEW-SCRIPT" && x.pkg === "b")!;
    expect(hit.severity).toBe("high");
  });
  test("AC3.4 same-version integrity change ⇒ critical; registry change ⇒ high", () => {
    const fi = diff(base(), [rec("a", { integrity: "sha512-EVIL" }), rec("b")]);
    expect(fi.find((x) => x.ruleId === "WG-DIFF-INTEGRITY" && x.pkg === "a")!.severity).toBe("critical");
    const fr = diff(base(), [rec("a", { resolved: "https://evil.example/a.tgz", registryHost: "evil.example" }), rec("b")]);
    expect(fr.find((x) => x.ruleId === "WG-DIFF-REGISTRY" && x.pkg === "a")!.severity).toBe("high");
  });
  test("AC3.5 identical inventory ⇒ empty diff", () => {
    const inv = [rec("a"), rec("b")];
    expect(diff(snapshot(inv), inv)).toEqual([]);
  });
});
