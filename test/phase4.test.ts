import { test, expect, describe } from "bun:test";
import { editDistance, typosquatFindings, policyFindings, TOP_NAMES, type PackageRecord } from "../src/index";

describe("AC4.1 edit distance", () => {
  test("known pairs", () => {
    expect(editDistance("abc", "abc")).toBe(0);
    expect(editDistance("ab", "ba")).toBe(1); // adjacent transposition
    expect(editDistance("lodash", "lodahs")).toBe(1); // transposition
    expect(editDistance("kitten", "sitting")).toBe(3);
    expect(editDistance("react", "reactt")).toBe(1); // insertion
  });
});

describe("AC4.2 typosquat", () => {
  const popular = ["react", "lodash", "express"];
  test("near-miss flagged by distance; exact & unrelated not", () => {
    const f = typosquatFindings(["reactt", "reactjs", "react", "zzzzzz"], popular);
    expect(f.find((x) => x.pkg === "reactt")!.severity).toBe("high"); // d1
    expect(f.find((x) => x.pkg === "reactjs")!.severity).toBe("medium"); // d2
    expect(f.some((x) => x.pkg === "react")).toBe(false); // exact
    expect(f.some((x) => x.pkg === "zzzzzz")).toBe(false); // unrelated
  });
  test("bundled list is non-empty", () => {
    expect(TOP_NAMES.length).toBeGreaterThan(50);
  });
});

describe("AC4.3 integrity/registry policy", () => {
  const rec = (p: Partial<PackageRecord>): PackageRecord => ({
    name: "p", version: "1.0.0", resolved: "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
    integrity: "sha512-A", registryHost: "registry.npmjs.org", hasInstallScript: false, dev: false, packageManager: "npm", ...p,
  });
  test("flags http, unknown registry, missing integrity", () => {
    const f = policyFindings([
      rec({ name: "insecure", resolved: "http://registry.npmjs.org/x.tgz" }),
      rec({ name: "weird", resolved: "https://evil.example/x.tgz", registryHost: "evil.example" }),
      rec({ name: "noint", integrity: null }),
    ]);
    expect(f.find((x) => x.pkg === "insecure")!.ruleId).toBe("WG-INSECURE-RESOLVED");
    expect(f.some((x) => x.pkg === "weird" && x.ruleId === "WG-UNKNOWN-REGISTRY")).toBe(true);
    expect(f.some((x) => x.pkg === "noint" && x.ruleId === "WG-NO-INTEGRITY")).toBe(true);
  });
  test("allowlist suppresses", () => {
    const f = policyFindings(
      [rec({ name: "weird", resolved: "https://evil.example/x.tgz", registryHost: "evil.example", integrity: null })],
      { allowedHosts: ["registry.npmjs.org", "evil.example"], allowMissingIntegrity: true },
    );
    expect(f).toEqual([]);
  });
});
