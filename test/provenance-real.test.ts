// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { verifyRegistrySignature, resetProvenanceKeyCache, sha256Hex } from "../src/provenance/verify";
import { existsSync, readFileSync } from "node:fs";

// Real-world fixture data for the verification path. Captured from the
// public npm registry; the signatures are public and verifiable.
const FIXTURE_DIR = "test/fixtures/provenance";

interface RegistryKey {
  expires: string | null;
  keyid: string;
  key: string;
}

describe("registry-signature verification (real keys + signatures)", () => {
  test("bundled npm registry keys are loaded", () => {
    expect(existsSync("data/npm-registry-keys.json")).toBe(true);
    const j = JSON.parse(readFileSync("data/npm-registry-keys.json", "utf8")) as { keys: RegistryKey[] };
    expect(j.keys.length).toBeGreaterThanOrEqual(1);
  });

  test("missing signatures returns WG-PROVENANCE-MISSING (low)", () => {
    resetProvenanceKeyCache();
    const r = verifyRegistrySignature("foo", "1.0.0", "sha512-A", []);
    expect(r?.ruleId).toBe("WG-PROVENANCE-MISSING");
  });

  test("bogus signature returns WG-PROVENANCE-INVALID (critical)", () => {
    resetProvenanceKeyCache();
    const r = verifyRegistrySignature("foo", "1.0.0", "sha512-A", [
      {
        keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
        sig: Buffer.from("not a valid signature").toString("base64"),
      },
    ]);
    expect(r?.ruleId).toBe("WG-PROVENANCE-INVALID");
    expect(r?.severity).toBe("critical");
  });

  test("unknown keyid returns WG-PROVENANCE-INVALID", () => {
    resetProvenanceKeyCache();
    const r = verifyRegistrySignature("foo", "1.0.0", "sha512-A", [
      { keyid: "SHA256:not-a-real-keyid", sig: "AAAA" },
    ]);
    expect(r?.ruleId).toBe("WG-PROVENANCE-INVALID");
  });

  test("real npm signature for sigstore@3.1.0 verifies (current key)", () => {
    if (!existsSync(`${FIXTURE_DIR}/sigstore-3.1.0.json`)) return; // fixture absent — test skipped
    const fix = JSON.parse(readFileSync(`${FIXTURE_DIR}/sigstore-3.1.0.json`, "utf8")) as {
      pkg: string;
      version: string;
      integrity: string;
      signatures: Array<{ keyid: string; sig: string }>;
    };
    resetProvenanceKeyCache();
    const r = verifyRegistrySignature(fix.pkg, fix.version, fix.integrity, fix.signatures);
    // Either null (verified with current key) or WG-PROVENANCE-EXPIRED-KEY (verified with old key) — both prove the signature was valid.
    expect(r === null || r.ruleId === "WG-PROVENANCE-EXPIRED-KEY").toBe(true);
  });

  test("real npm signature for lodash@4.17.21 verifies (expired key still proves history)", () => {
    if (!existsSync(`${FIXTURE_DIR}/lodash-4.17.21.json`)) return; // fixture absent — test skipped
    const fix = JSON.parse(readFileSync(`${FIXTURE_DIR}/lodash-4.17.21.json`, "utf8")) as {
      pkg: string;
      version: string;
      integrity: string;
      signatures: Array<{ keyid: string; sig: string }>;
    };
    resetProvenanceKeyCache();
    const r = verifyRegistrySignature(fix.pkg, fix.version, fix.integrity, fix.signatures);
    expect(r?.ruleId).toBe("WG-PROVENANCE-EXPIRED-KEY");
    expect(r?.severity).toBe("low");
  });

  test("sha256Hex helper is deterministic", () => {
    expect(sha256Hex("hello")).toBe(sha256Hex(Buffer.from("hello")));
  });
});
