// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { parseLockfile, WormguardError } from "../src/index";

describe("lockfile DoS guards (red-team C3)", () => {
  test("normally-deep lockfile (200 levels) parses successfully without stack overflow", () => {
    let nested: any = { version: "1.0.0", dependencies: {} };
    let cur: any = nested;
    for (let i = 0; i < 200; i++) {
      cur.dependencies = { [`p${i}`]: { version: "1.0.0", dependencies: {} } };
      cur = cur.dependencies[`p${i}`];
    }
    const out = parseLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: nested.dependencies }));
    expect(out.length).toBeGreaterThanOrEqual(200);
  });

  test("pathologically deep lockfile (10,000 levels) throws WormguardError without crashing", () => {
    let nested: any = { version: "1.0.0", dependencies: {} };
    let cur: any = nested;
    for (let i = 0; i < 10_000; i++) {
      cur.dependencies = { [`p${i}`]: { version: "1.0.0", dependencies: {} } };
      cur = cur.dependencies[`p${i}`];
    }
    expect(() =>
      parseLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: nested.dependencies })),
    ).toThrow(WormguardError);
  });
});
