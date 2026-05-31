// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  snapshot,
  serializeBaseline,
  parseBaseline,
  diff,
  computeScriptsHash,
  type Baseline,
  type PackageRecord,
  WormguardError,
} from "../src/index";
import type { InstalledPackage } from "../src/inventory";

const rec = (p: Partial<PackageRecord>): PackageRecord => ({
  name: "x",
  version: "1.0.0",
  resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
  integrity: "sha512-A",
  registryHost: "registry.npmjs.org",
  hasInstallScript: false,
  dev: false,
  packageManager: "npm",
  ...p,
});

const inst = (name: string, scripts: Record<string, string>): InstalledPackage => ({
  name,
  dir: `/x/${name}`,
  scripts,
  layout: "npm",
  version: "1.0.0",
});

describe("baseline v2", () => {
  test("snapshot includes scriptsHash when installed package supplies bodies", () => {
    const b = snapshot([rec({ name: "esbuild", hasInstallScript: true })], [inst("esbuild", { postinstall: "node install.js" })]);
    expect(b.version).toBe(2);
    expect(b.packages.esbuild?.scriptsHash).toBeString();
  });

  test("scriptsHash is null when no installed entry available", () => {
    const b = snapshot([rec({ name: "esbuild", hasInstallScript: true })]);
    expect(b.packages.esbuild?.scriptsHash).toBeNull();
  });

  test("computeScriptsHash is order-stable across declaration order", () => {
    const a = computeScriptsHash({ scripts: { postinstall: "x", preinstall: "y" } as Record<string, string | undefined> });
    const b = computeScriptsHash({ scripts: { preinstall: "y", postinstall: "x" } as Record<string, string | undefined> });
    expect(a).toBe(b);
  });

  test("v1 baseline parse-upgrades to v2 with scriptsHash:null", () => {
    const v1: { version: 1; packages: Record<string, unknown> } = {
      version: 1,
      packages: { foo: { version: "1.0.0", integrity: null, resolved: null, registryHost: null, hasInstallScript: false } },
    };
    const upgraded = parseBaseline(JSON.stringify(v1));
    expect((upgraded as Baseline).version).toBe(2);
    expect(upgraded.packages.foo?.scriptsHash).toBeNull();
  });

  test("unrecognized version throws", () => {
    expect(() => parseBaseline(`{"version":99,"packages":{}}`)).toThrow(WormguardError);
  });

  test("script body change for unchanged version emits WG-DIFF-SCRIPT-BODY (critical)", () => {
    const old = snapshot([rec({ name: "lib", hasInstallScript: true })], [inst("lib", { postinstall: "node a.js" })]);
    const findings = diff(old, [rec({ name: "lib", hasInstallScript: true })], [inst("lib", { postinstall: "node EVIL.js" })]);
    const hit = findings.find((f) => f.ruleId === "WG-DIFF-SCRIPT-BODY");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("critical");
  });

  test("identical body across snapshots: no script-body finding", () => {
    const installed = [inst("lib", { postinstall: "node a.js" })];
    const old = snapshot([rec({ name: "lib", hasInstallScript: true })], installed);
    const findings = diff(old, [rec({ name: "lib", hasInstallScript: true })], installed);
    expect(findings.some((f) => f.ruleId === "WG-DIFF-SCRIPT-BODY")).toBe(false);
  });

  test("WG-DIFF-NEW-SCRIPT still fires when hasInstallScript flips false->true", () => {
    const old = snapshot([rec({ name: "lib", hasInstallScript: false })]);
    const findings = diff(old, [rec({ name: "lib", hasInstallScript: true })], [inst("lib", { postinstall: "x" })]);
    expect(findings.some((f) => f.ruleId === "WG-DIFF-NEW-SCRIPT")).toBe(true);
  });

  test("v1->v2 baseline with no recorded scriptsHash does NOT emit body-change findings (no signal)", () => {
    const v1: { version: 1; packages: Record<string, unknown> } = {
      version: 1,
      packages: { lib: { version: "1.0.0", integrity: "sha512-A", resolved: "https://r/x.tgz", registryHost: "r", hasInstallScript: true } },
    };
    const upgraded = parseBaseline(JSON.stringify(v1));
    const findings = diff(upgraded, [rec({ name: "lib", integrity: "sha512-A", resolved: "https://r/x.tgz", registryHost: "r", hasInstallScript: true })], [inst("lib", { postinstall: "anything" })]);
    expect(findings.some((f) => f.ruleId === "WG-DIFF-SCRIPT-BODY")).toBe(false);
  });

  test("serialize -> parse roundtrip is byte-stable for v2", () => {
    const b = snapshot([rec({ name: "a" }), rec({ name: "b" })]);
    const text = serializeBaseline(b);
    const re = serializeBaseline(parseBaseline(text));
    expect(re).toBe(text);
  });
});
