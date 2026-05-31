// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { verifyBundle } from "../src/provenance/verify";

// Fixture: a real npm provenance bundle for sigstore@3.1.0, captured at
// test/fixtures/provenance/sigstore-3.1.0-bundle.json + .tgz. We use it
// to assert that:
//   (1) calling verifyBundle with the WRONG expectedSubjectName REJECTS,
//       even though the bundle's signature itself is valid.
//   (2) calling verifyBundle with the WRONG expectedDigest REJECTS.
// These prove the cross-package and cross-artifact replay defenses
// (red-team C4).

const BUNDLE_PATH = "test/fixtures/provenance/sigstore-3.1.0-bundle.json";
const TARBALL_PATH = "test/fixtures/provenance/sigstore-3.1.0.tgz";

describe("verifyBundle subject binding (red-team C4)", () => {
  test("expectedSubjectName mismatch returns critical INVALID even with a valid bundle", async () => {
    if (!existsSync(BUNDLE_PATH) || !existsSync(TARBALL_PATH)) {
      // Fixtures not committed (network-only); skip.
      return;
    }
    const bundle = JSON.parse(readFileSync(BUNDLE_PATH, "utf8"));
    const tarball = readFileSync(TARBALL_PATH);
    const f = await verifyBundle("evil-pkg", bundle, tarball, {
      timeoutMs: 4000,
      expectedSubjectName: "pkg:npm/evil-pkg@9.9.9", // wrong
    });
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
    expect(f?.ruleId).toBe("WG-PROVENANCE-INVALID");
  });

  test("expectedDigest mismatch returns critical INVALID even with the right subject name", async () => {
    if (!existsSync(BUNDLE_PATH) || !existsSync(TARBALL_PATH)) return;
    const bundle = JSON.parse(readFileSync(BUNDLE_PATH, "utf8"));
    const tarball = readFileSync(TARBALL_PATH);
    // Recover the real subject name from the bundle (so the only mismatch is
    // the digest).
    const env = bundle.dsseEnvelope as { payload: string } | undefined;
    if (!env) return;
    const stmt = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
    const realSubject = stmt.subject?.[0]?.name as string | undefined;
    if (!realSubject) return;
    const wrongDigest = createHash("sha512").update("not the tarball").digest("hex");
    const f = await verifyBundle("sigstore", bundle, tarball, {
      timeoutMs: 4000,
      expectedSubjectName: realSubject,
      expectedDigest: wrongDigest,
    });
    expect(f).not.toBeNull();
    expect(f?.ruleId).toBe("WG-PROVENANCE-INVALID");
  });
});
