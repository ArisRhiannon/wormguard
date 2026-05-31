// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import {
  provenanceContextFromLockEntry,
  provenanceFindings,
  verifyBundle,
} from "../src/provenance/verify";

describe("provenance: lockfile entry inspection", () => {
  test("detects registry signatures", () => {
    const c = provenanceContextFromLockEntry("react", "18.0.0", {
      signatures: [{ keyid: "SHA256:abc", sig: "MEUCIQ..." }],
    });
    expect(c.hasRegistrySignatures).toBe(true);
    expect(c.hasAttestations).toBe(false);
  });

  test("detects dist.attestations object", () => {
    const c = provenanceContextFromLockEntry("react", "18.0.0", {
      dist: { attestations: { url: "https://...", provenance: { predicateType: "..." } } },
    });
    expect(c.hasAttestations).toBe(true);
  });

  test("flags missing provenance as low", () => {
    const c = provenanceContextFromLockEntry("foo", "1.0.0", {});
    const f = provenanceFindings(c);
    expect(f.some((x) => x.ruleId === "WG-PROVENANCE-MISSING")).toBe(true);
    expect(f.find((x) => x.ruleId === "WG-PROVENANCE-MISSING")?.severity).toBe("low");
  });

  test("signed but no attestation flags WG-PROVENANCE-NO-ATTESTATION (low)", () => {
    const c = provenanceContextFromLockEntry("foo", "1.0.0", {
      signatures: [{ keyid: "x", sig: "y" }],
    });
    const f = provenanceFindings(c);
    expect(f.some((x) => x.ruleId === "WG-PROVENANCE-NO-ATTESTATION")).toBe(true);
  });

  test("fully attested: no provenance findings", () => {
    const c = provenanceContextFromLockEntry("foo", "1.0.0", {
      signatures: [{ keyid: "x", sig: "y" }],
      dist: { attestations: { provenance: {} } },
    });
    const f = provenanceFindings(c);
    expect(f.length).toBe(0);
  });
});

describe("provenance: bundle verification", () => {
  test("a bogus bundle returns a critical finding (does not throw)", async () => {
    const f = await verifyBundle("foo", { fake: "bundle" }, Buffer.from("payload"));
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
    expect(f?.ruleId).toBe("WG-PROVENANCE-INVALID");
  });
});
