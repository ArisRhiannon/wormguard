import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseLockfile, scanNodeModules, WormguardError } from "../src/index";

const tmp = mkdtempSync(join(tmpdir(), "wormguard-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const V3 = JSON.stringify({
  name: "proj", lockfileVersion: 3,
  packages: {
    "": { name: "proj", version: "1.0.0" },
    "node_modules/foo": { version: "1.2.3", resolved: "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz", integrity: "sha512-AAA", hasInstallScript: true },
    "node_modules/@scope/bar": { version: "0.1.0", resolved: "https://registry.npmjs.org/@scope/bar/-/bar-0.1.0.tgz", integrity: "sha512-BBB", dev: true },
  },
});

const V1 = JSON.stringify({
  name: "proj", lockfileVersion: 1,
  dependencies: {
    foo: { version: "1.2.3", resolved: "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz", integrity: "sha1-X", dependencies: { bar: { version: "0.0.1", resolved: "https://registry.npmjs.org/bar/-/bar-0.0.1.tgz" } } },
  },
});

describe("AC1.1/1.2/1.3 lockfile parsing", () => {
  test("v3 packages → normalized records", () => {
    const recs = parseLockfile(V3);
    const foo = recs.find((r) => r.name === "foo")!;
    expect(foo.version).toBe("1.2.3");
    expect(foo.registryHost).toBe("registry.npmjs.org");
    expect(foo.hasInstallScript).toBe(true);
    expect(foo.integrity).toBe("sha512-AAA");
    const bar = recs.find((r) => r.name === "@scope/bar")!;
    expect(bar.dev).toBe(true);
    expect(bar.hasInstallScript).toBe(false);
    expect(recs.some((r) => r.name === "proj")).toBe(false); // root excluded
  });
  test("v1 dependencies tree → same shape, nested included", () => {
    const recs = parseLockfile(V1);
    expect(recs.find((r) => r.name === "foo")?.version).toBe("1.2.3");
    expect(recs.find((r) => r.name === "bar")?.version).toBe("0.0.1");
    expect(recs.find((r) => r.name === "foo")?.hasInstallScript).toBe(false);
  });
  test("AC1.3 missing resolved → null host, no throw", () => {
    const recs = parseLockfile(JSON.stringify({ packages: { "node_modules/x": { version: "1.0.0" } } }));
    expect(recs[0]?.registryHost).toBeNull();
    expect(recs[0]?.resolved).toBeNull();
  });
  test("AC1.5 malformed JSON throws WormguardError", () => {
    expect(() => parseLockfile("{not json")).toThrow(WormguardError);
  });
});

describe("AC1.4 node_modules scan", () => {
  const proj = join(tmp, "proj");
  const mk = (p: string, obj: unknown) => { mkdirSync(join(proj, p), { recursive: true }); writeFileSync(join(proj, p, "package.json"), JSON.stringify(obj)); };
  mk("node_modules/foo", { name: "foo", scripts: { postinstall: "node setup.js", build: "tsc" } });
  mk("node_modules/@scope/bar", { name: "@scope/bar", scripts: { test: "echo ok" } });
  mkdirSync(join(proj, "node_modules", ".bin"), { recursive: true });

  test("extracts lifecycle scripts incl. scoped, ignores .bin & non-lifecycle", () => {
    const pkgs = scanNodeModules(proj);
    const foo = pkgs.find((p) => p.name === "foo")!;
    expect(foo.scripts.postinstall).toBe("node setup.js");
    expect(foo.scripts.preinstall).toBeUndefined();
    expect(pkgs.find((p) => p.name === "@scope/bar")!.scripts.postinstall).toBeUndefined();
    expect(pkgs.some((p) => p.name === ".bin")).toBe(false);
  });
  test("missing node_modules → []", () => {
    expect(scanNodeModules(join(tmp, "nope"))).toEqual([]);
  });
});
