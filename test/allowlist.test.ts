// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  scriptSha256,
  isAllowlistedPackage,
  checkFingerprint,
  fingerprintDriftFinding,
} from "../src/corpus/allowlist";
import { readFileSync, existsSync } from "node:fs";

describe("script-fingerprint allowlist", () => {
  test("scriptSha256 is deterministic and case-sensitive on body", () => {
    expect(scriptSha256("node install.js")).toBe(scriptSha256("node install.js"));
    expect(scriptSha256("node install.js")).not.toBe(scriptSha256("Node install.js"));
  });

  test("isAllowlistedPackage recognizes bundled packages", () => {
    if (!existsSync("data/script-allowlist.json")) return; // populator not run
    expect(isAllowlistedPackage("esbuild")).toBe(true);
    expect(isAllowlistedPackage("sharp")).toBe(true);
    expect(isAllowlistedPackage("definitely-not-a-real-package")).toBe(false);
  });

  test("user-supplied extra entries are honored", () => {
    expect(isAllowlistedPackage("custom-pkg", { "custom-pkg": ["abc"] })).toBe(true);
    expect(isAllowlistedPackage("not-here", { other: ["abc"] })).toBe(false);
  });

  test("checkFingerprint returns 'match' for a real bundled hash", () => {
    if (!existsSync("data/script-allowlist.json")) return;
    const al = JSON.parse(readFileSync("data/script-allowlist.json", "utf8")) as {
      packages: Record<string, string[]>;
      origins: Record<string, { hash: string; body: string }[]>;
    };
    const pkgWithOrigins = Object.keys(al.origins).find(
      (k) => Array.isArray(al.origins[k]) && (al.origins[k] as { body: string }[]).length > 0,
    );
    if (!pkgWithOrigins) return;
    const ent = al.origins[pkgWithOrigins]?.[0];
    if (!ent) return;
    const result = checkFingerprint(pkgWithOrigins, ent.body);
    expect(result.status).toBe("match");
    expect(result.sha256).toBe(ent.hash);
  });

  test("checkFingerprint returns 'drift' for a known package with unknown body", () => {
    if (!existsSync("data/script-allowlist.json")) return;
    const al = JSON.parse(readFileSync("data/script-allowlist.json", "utf8")) as {
      packages: Record<string, string[]>;
    };
    const pkgs = Object.keys(al.packages);
    const known = pkgs.find((k) => al.packages[k] && (al.packages[k] as string[]).length > 0);
    if (!known) return;
    const result = checkFingerprint(known, "this is definitely not the real install script body");
    expect(result.status).toBe("drift");
  });

  test("checkFingerprint returns 'unknown' for an unknown package", () => {
    const result = checkFingerprint("not-on-allowlist", "anything");
    expect(result.status).toBe("unknown");
  });

  test("user extras participate in match/drift logic", () => {
    const body = "foo bar";
    const sha = scriptSha256(body);
    const ok = checkFingerprint("custom-pkg", body, { "custom-pkg": [sha] });
    expect(ok.status).toBe("match");
    const drift = checkFingerprint("custom-pkg", "different body", { "custom-pkg": [sha] });
    expect(drift.status).toBe("drift");
  });

  test("fingerprintDriftFinding produces a critical finding", () => {
    const f = fingerprintDriftFinding("esbuild", "deadbeef".repeat(8), "postinstall");
    expect(f.severity).toBe("critical");
    expect(f.ruleId).toBe("WG-SCRIPT-FINGERPRINT-DRIFT");
    expect(f.pkg).toBe("esbuild");
  });
});
