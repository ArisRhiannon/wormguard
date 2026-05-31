// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectLockfiles, isYarnBerry } from "../src/pm/detect";
import { parsePnpmLockfile } from "../src/pm/pnpm";
import { parseYarnClassicLockfile } from "../src/pm/yarn-classic";
import { parseYarnBerryLockfile } from "../src/pm/yarn-berry";
import { parseBunLockfile } from "../src/pm/bun";
import { inventoryFromLockfiles } from "../src/pm/index";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "wg-pm-"));
}

describe("pm/detect", () => {
  test("detects npm package-lock.json", () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), "{}");
    const r = detectLockfiles(d);
    expect(r.length).toBe(1);
    expect(r[0]?.packageManager).toBe("npm");
  });
  test("detects pnpm-lock.yaml", () => {
    const d = tmp();
    writeFileSync(join(d, "pnpm-lock.yaml"), "lockfileVersion: '6.0'\npackages: {}\n");
    const r = detectLockfiles(d);
    expect(r[0]?.packageManager).toBe("pnpm");
  });
  test("isYarnBerry detects __metadata block", () => {
    expect(isYarnBerry("__metadata:\n  version: 6\n")).toBe(true);
    expect(isYarnBerry("# yarn lockfile v1\n")).toBe(false);
  });
  test("detects yarn-classic vs yarn-berry from yarn.lock content", () => {
    const cls = tmp();
    writeFileSync(join(cls, "yarn.lock"), `# yarn lockfile v1\n\n"foo@^1.0.0":\n  version "1.0.0"\n  resolved "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"\n  integrity sha512-AAA\n`);
    const ber = tmp();
    writeFileSync(join(ber, "yarn.lock"), `__metadata:\n  version: 6\n\n"foo@npm:1.0.0":\n  version: 1.0.0\n  resolution: "foo@npm:1.0.0"\n  checksum: sha512-AAA\n`);
    expect(detectLockfiles(cls)[0]?.packageManager).toBe("yarn-classic");
    expect(detectLockfiles(ber)[0]?.packageManager).toBe("yarn-berry");
  });
  test("detects bun.lock", () => {
    const d = tmp();
    writeFileSync(
      join(d, "bun.lock"),
      `{ "lockfileVersion": 1, "packages": { "foo": ["foo@1.0.0", "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz", {}, "sha512-AAA"] } }`,
    );
    const r = detectLockfiles(d);
    expect(r[0]?.packageManager).toBe("bun");
  });
});

describe("pm/pnpm", () => {
  test("parses a v9 pnpm-lock.yaml with packages + snapshots", () => {
    const text = `lockfileVersion: '9.0'
importers:
  .:
    dependencies: {}
packages:
  /lodash@4.17.21:
    resolution:
      tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
      integrity: sha512-XYZ
    requiresBuild: false
  /esbuild@0.20.0:
    resolution:
      tarball: https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz
      integrity: sha512-ABC
    requiresBuild: true
snapshots:
  /lodash@4.17.21:
    dev: false
  /esbuild@0.20.0:
    dev: true
`;
    const r = parsePnpmLockfile(text);
    expect(r.length).toBe(2);
    const lodash = r.find((p) => p.name === "lodash");
    const esbuild = r.find((p) => p.name === "esbuild");
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.integrity).toBe("sha512-XYZ");
    expect(lodash?.registryHost).toBe("registry.npmjs.org");
    expect(esbuild?.hasInstallScript).toBe(true);
    expect(esbuild?.dev).toBe(true);
    expect(lodash?.packageManager).toBe("pnpm");
  });
  test("parses v7+ key form without leading slash", () => {
    const text = `lockfileVersion: '7.0'\npackages:\n  'react@18.0.0':\n    resolution:\n      tarball: https://registry.npmjs.org/react/-/react-18.0.0.tgz\n      integrity: sha512-XX\n`;
    const r = parsePnpmLockfile(text);
    expect(r.length).toBe(1);
    expect(r[0]?.name).toBe("react");
  });
});

describe("pm/yarn-classic", () => {
  test("parses a v1 yarn.lock", () => {
    const text = `# yarn lockfile v1

"lodash@^4.17.21":
  version "4.17.21"
  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-XYZ
`;
    const r = parseYarnClassicLockfile(text);
    expect(r.length).toBe(1);
    expect(r[0]?.name).toBe("lodash");
    expect(r[0]?.version).toBe("4.17.21");
    expect(r[0]?.resolved).toBe("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");
    expect(r[0]?.integrity).toBe("sha512-XYZ");
    expect(r[0]?.packageManager).toBe("yarn-classic");
  });
  test("parses scoped package keys", () => {
    const text = `"@scope/pkg@^1.0.0":\n  version "1.0.0"\n  resolved "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"\n  integrity sha512-A\n`;
    const r = parseYarnClassicLockfile(text);
    expect(r[0]?.name).toBe("@scope/pkg");
  });
});

describe("pm/yarn-berry", () => {
  test("parses a berry lockfile", () => {
    const text = `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 8b574...
  languageName: node
  linkType: hard

"@scope/pkg@npm:^1.0.0":
  version: 1.0.0
  resolution: "@scope/pkg@npm:1.0.0"
  checksum: ab12...
`;
    const r = parseYarnBerryLockfile(text);
    expect(r.length).toBe(2);
    const scoped = r.find((p) => p.name === "@scope/pkg");
    expect(scoped?.version).toBe("1.0.0");
    expect(scoped?.packageManager).toBe("yarn-berry");
  });
});

describe("pm/bun", () => {
  test("parses bun.lock JSONC", () => {
    const text = `{
      // a comment
      "lockfileVersion": 1,
      "packages": {
        "lodash": ["lodash@4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", {}, "sha512-XYZ"],
        "@scope/pkg": ["@scope/pkg@1.0.0", "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", {}, "sha512-A"],
      },
    }`;
    const r = parseBunLockfile(text);
    expect(r.length).toBe(2);
    const lodash = r.find((p) => p.name === "lodash");
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.integrity).toBe("sha512-XYZ");
    expect(lodash?.packageManager).toBe("bun");
  });
  test("rejects bun.lockb (binary)", () => {
    expect(() => parseBunLockfile("", true)).toThrow();
  });
});

describe("pm/inventoryFromLockfiles integration", () => {
  test("loads npm lockfile end-to-end", () => {
    const d = tmp();
    writeFileSync(
      join(d, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "p" },
          "node_modules/foo": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            integrity: "sha512-A",
            hasInstallScript: true,
          },
        },
      }),
    );
    const r = inventoryFromLockfiles(d);
    expect(r.lockfilesUsed[0]?.packageManager).toBe("npm");
    expect(r.records.length).toBe(1);
    expect(r.records[0]?.name).toBe("foo");
  });
  test("a malformed lockfile is skipped, not crashed", () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), "not json");
    const r = inventoryFromLockfiles(d);
    expect(r.records.length).toBe(0);
  });
});
