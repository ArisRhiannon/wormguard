// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Provenance verification.
//
// Two distinct kinds of "provenance" exist in the npm ecosystem and we
// support both:
//
//   1. Registry signatures (`signatures: [{keyid, sig}]` in the lockfile,
//      and the `signatures` array on `dist` in the registry packument).
//      These are ECDSA signatures over the package's integrity by the
//      *npm registry's* signing key, NOT sigstore. We verify them with
//      Node's built-in crypto using the bundled
//      data/npm-registry-keys.json (fetched at release time from
//      https://registry.npmjs.org/-/npm/v1/keys).
//
//   2. Build provenance (npm publish --provenance). These are full
//      Sigstore bundles (certs + Rekor log entry) embedded as
//      `dist.attestations.url` payloads. We verify them with sigstore-js
//      (which delegates the cryptography to its bundled trust roots
//      shipped via TUF). For npm-style provenance, the bundle is in
//      "public key" mode keyed by a SHA256 `hint` — our `verifyBundle`
//      resolves that hint against the same bundled npm registry keys.
//
// The audit pipeline reads the lockfile evidence offline and, when given
// a bundle file or fetched payload, can verify it offline-after-fetch.

import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { createPublicKey, createVerify, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { verify as sigstoreVerify } from "sigstore";
import type { Finding } from "../types";

export interface ProvenanceContext {
  /** Package name. */
  pkg: string;
  /** Package version. */
  version: string;
  /** True if the lockfile entry has a non-empty `signatures` array. */
  hasRegistrySignatures: boolean;
  /** True if the package metadata advertises `dist.attestations`. */
  hasAttestations: boolean;
  /** True if a sigstore bundle JSON file exists in the cache for this version. */
  hasLocalSigstoreBundle: boolean;
  /** Path of the bundle file, if any. */
  localBundlePath?: string;
}

/** Inspect `package-lock.json` style entries for provenance evidence. */
export function provenanceContextFromLockEntry(
  pkg: string,
  version: string,
  lockEntry: { signatures?: unknown; dist?: unknown },
): ProvenanceContext {
  const signatures = Array.isArray(lockEntry.signatures) ? lockEntry.signatures : [];
  const dist = lockEntry.dist as { attestations?: unknown } | undefined;
  const attestations = dist && typeof dist === "object" ? dist.attestations : undefined;
  return {
    pkg,
    version,
    hasRegistrySignatures: signatures.length > 0,
    hasAttestations: typeof attestations === "object" && attestations !== null,
    hasLocalSigstoreBundle: false,
  };
}

/** Look for a cached sigstore bundle in node_modules/.../sigstore-bundles or in
 *  the wormguard cache directory next to package.json. */
export function findLocalBundle(
  pkgRoot: string,
  pkg: string,
  version: string,
): string | null {
  const candidates = [
    join(pkgRoot, ".wormguard", "bundles", `${pkg.replace("/", "__")}@${version}.json`),
    join(pkgRoot, "node_modules", pkg, ".sigstore-bundle.json"),
    join(pkgRoot, "node_modules", pkg, ".attestations", "bundle.json"),
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

// ---------------------------------------------------------------------------
// Registry-signature verification (ECDSA P-256 over the package integrity)
// ---------------------------------------------------------------------------

interface NpmRegistryKey {
  expires: string | null;
  keyid: string;
  keytype: string;
  scheme: string;
  /** SubjectPublicKeyInfo, base64-encoded. */
  key: string;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const REGISTRY_KEYS_PATH = join(HERE, "..", "..", "data", "npm-registry-keys.json");

let cachedRegistryKeys: Map<string, NpmRegistryKey> | null = null;
function loadRegistryKeys(): Map<string, NpmRegistryKey> {
  if (cachedRegistryKeys) return cachedRegistryKeys;
  const out = new Map<string, NpmRegistryKey>();
  if (!existsSync(REGISTRY_KEYS_PATH)) {
    cachedRegistryKeys = out;
    return out;
  }
  try {
    const json = JSON.parse(readFileSync(REGISTRY_KEYS_PATH, "utf8")) as { keys?: NpmRegistryKey[] };
    if (Array.isArray(json.keys)) {
      for (const k of json.keys) {
        if (k && typeof k.keyid === "string" && typeof k.key === "string") out.set(k.keyid, k);
      }
    }
  } catch {
    /* fall through */
  }
  cachedRegistryKeys = out;
  return out;
}

/** Reset cache (tests). */
export function resetProvenanceKeyCache(): void {
  cachedRegistryKeys = null;
}

/**
 * Verify an npm registry signature: the registry signs the string
 * `<package-name>@<version>:<integrity>` with one of the keys advertised
 * at `https://registry.npmjs.org/-/npm/v1/keys`.
 *
 * Returns null on success, or a Finding describing the failure mode.
 */
export function verifyRegistrySignature(
  pkg: string,
  version: string,
  integrity: string,
  signatures: Array<{ keyid?: string; sig?: string }>,
): Finding | null {
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return {
      ruleId: "WG-PROVENANCE-MISSING",
      severity: "low",
      pkg,
      message: `no registry signatures attached to ${pkg}@${version}`,
    };
  }
  const keys = loadRegistryKeys();
  if (keys.size === 0) {
    return {
      ruleId: "WG-PROVENANCE-NO-KEYS",
      severity: "medium",
      pkg,
      message:
        "registry signatures present but bundled npm registry public keys are not available; cannot verify",
    };
  }
  const message = `${pkg}@${version}:${integrity}`;
  let usedExpiredKey = false;
  for (const s of signatures) {
    if (typeof s.keyid !== "string" || typeof s.sig !== "string") continue;
    const k = keys.get(s.keyid);
    if (!k) continue;
    const expired = k.expires !== null && new Date(k.expires).getTime() < Date.now();
    try {
      const der = Buffer.from(k.key, "base64");
      const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
      const ok = createVerify("SHA256").update(message).verify(
        { key: publicKey, dsaEncoding: "der" },
        Buffer.from(s.sig, "base64"),
      );
      if (ok) {
        if (expired) {
          // Cryptographically valid, but signed with a key that has since
          // expired. We accept the proof but emit a low advisory so
          // operators know to look for a newer signature.
          return {
            ruleId: "WG-PROVENANCE-EXPIRED-KEY",
            severity: "low",
            pkg,
            message: `registry signature verified, but the signing key (${s.keyid}) has expired (${k.expires}). Re-sign with a current key when possible.`,
          };
        }
        return null;
      }
      if (expired) usedExpiredKey = true;
    } catch {
      /* try the next signature */
    }
  }
  return {
    ruleId: "WG-PROVENANCE-INVALID",
    severity: "critical",
    pkg,
    message: usedExpiredKey
      ? `none of the ${signatures.length} registry signature(s) verified (one used an expired key)`
      : `none of the ${signatures.length} registry signature(s) verified against the bundled npm registry keys`,
  };
}

// ---------------------------------------------------------------------------
// Sigstore bundle verification (npm publish --provenance)
// ---------------------------------------------------------------------------

/** Run sigstore-js verification on a user-supplied bundle + payload, AND
 *  bind the bundle's DSSE statement to the expected package identity.
 *
 *  Red-team C4 fix: previously `verifyBundle(pkg, bundleJson, payload)`
 *  only verified the cryptographic signature over the payload bytes. It
 *  did not check that the bundle's `subject[].name` matched `pkg@version`
 *  nor that the bundle's `subject[].digest.sha512` matched the integrity
 *  we expected. That made the API a confused deputy: an attacker could
 *  present a valid bundle for a package they control as if it were a
 *  bundle for the victim package.
 *
 *  Required fields:
 *    `expectedSubjectName`  e.g. "pkg:npm/lodash@4.17.21"
 *    `expectedDigest`       hex sha512 of the tarball, OR null to skip the
 *                           digest cross-check (only safe when the caller
 *                           already verified the digest separately).
 *
 *  Returns null on success, or a Finding describing the failure. */
export async function verifyBundle(
  pkg: string,
  bundleJson: unknown,
  payload: Buffer,
  opts: {
    timeoutMs?: number;
    expectedSubjectName: string;
    expectedDigest?: string | null;
  },
): Promise<Finding | null> {
  if (typeof opts.expectedSubjectName !== "string" || opts.expectedSubjectName.length === 0) {
    return {
      ruleId: "WG-PROVENANCE-INVALID",
      severity: "critical",
      pkg,
      message: "verifyBundle called without expectedSubjectName; refusing to verify (would be a confused deputy)",
    };
  }
  const timeoutMs = opts.timeoutMs ?? 4000;
  // Pull out the hint, if any.
  const hint = (() => {
    try {
      const b = bundleJson as { verificationMaterial?: { publicKey?: { hint?: unknown } } };
      const h = b?.verificationMaterial?.publicKey?.hint;
      return typeof h === "string" ? h : null;
    } catch {
      return null;
    }
  })();
  // Build a key selector for sigstore.verify if we have the key bundled.
  const keys = loadRegistryKeys();
  let keySelector: ((hint: string) => string | null) | undefined;
  if (hint) {
    const keyEntry = keys.get(hint);
    if (keyEntry) {
      const der = Buffer.from(keyEntry.key, "base64");
      const pem = createPublicKey({ key: der, format: "der", type: "spki" }).export({
        format: "pem",
        type: "spki",
      });
      const pemString = typeof pem === "string" ? pem : pem.toString("utf8");
      keySelector = (h: string) => (h === hint ? pemString : null);
    }
  }
  const work: Promise<Finding | null> = (async () => {
    try {
      if (keySelector) {
        await sigstoreVerify(bundleJson as never, payload, { keySelector } as never);
      } else {
        await sigstoreVerify(bundleJson as never, payload);
      }
    } catch (err) {
      return {
        ruleId: "WG-PROVENANCE-INVALID",
        severity: "critical",
        pkg,
        message: `sigstore provenance verification failed: ${(err as Error).message}`,
      };
    }
    // Cryptographic verification succeeded. Now bind the bundle's DSSE
    // statement to the package identity we expect.
    try {
      const env = (bundleJson as { dsseEnvelope?: { payload?: string }; messageSignature?: unknown })?.dsseEnvelope;
      if (!env || typeof env.payload !== "string") {
        // Some bundles use messageSignature instead of dsseEnvelope. In that
        // case the bundle does not contain a subject statement and we cannot
        // bind it to a package identity at all.
        return {
          ruleId: "WG-PROVENANCE-INVALID",
          severity: "critical",
          pkg,
          message:
            "sigstore bundle has no DSSE envelope; cannot verify package identity binding (bundle must be a build-provenance attestation)",
        };
      }
      const stmtJson = Buffer.from(env.payload, "base64").toString("utf8");
      const stmt = JSON.parse(stmtJson) as {
        subject?: Array<{ name?: string; digest?: Record<string, string> }>;
      };
      const subjects = Array.isArray(stmt.subject) ? stmt.subject : [];
      const subjMatch = subjects.find((s) => typeof s.name === "string" && s.name === opts.expectedSubjectName);
      if (!subjMatch) {
        return {
          ruleId: "WG-PROVENANCE-INVALID",
          severity: "critical",
          pkg,
          message: `sigstore bundle subject does not include "${opts.expectedSubjectName}"; bundle is for a different package (cross-package replay rejected). Subjects in bundle: ${subjects.map((s) => s.name ?? "<unknown>").slice(0, 3).join(", ")}`,
        };
      }
      if (typeof opts.expectedDigest === "string") {
        const want = opts.expectedDigest.toLowerCase();
        const got = (subjMatch.digest?.sha512 ?? subjMatch.digest?.sha256 ?? "").toLowerCase();
        if (!got || got !== want) {
          return {
            ruleId: "WG-PROVENANCE-INVALID",
            severity: "critical",
            pkg,
            message: `sigstore bundle subject digest does not match expected payload digest (want ${want.slice(0, 16)}…, got ${got.slice(0, 16) || "<empty>"}…). Bundle may be valid for a different artifact bytes.`,
          };
        }
      }
    } catch (err) {
      return {
        ruleId: "WG-PROVENANCE-INVALID",
        severity: "critical",
        pkg,
        message: `sigstore bundle subject parsing failed: ${(err as Error).message}`,
      };
    }
    return null;
  })();
  const timeout: Promise<Finding> = new Promise((resolve) => {
    setTimeout(
      () =>
        resolve({
          ruleId: "WG-PROVENANCE-INVALID",
          severity: "critical",
          pkg,
          message: `sigstore provenance verification timed out after ${timeoutMs}ms (TUF/network unavailable)`,
        }),
      timeoutMs,
    ).unref?.();
  });
  return Promise.race([work, timeout]);
}

/** Convenience: also expose a sha256 helper on the provenance namespace
 *  (some callers reach for it through this module). */
export function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** High-level: produce findings about missing/weak provenance for a package. */
export function provenanceFindings(ctx: ProvenanceContext): Finding[] {
  const out: Finding[] = [];
  if (!ctx.hasRegistrySignatures && !ctx.hasAttestations) {
    out.push({
      ruleId: "WG-PROVENANCE-MISSING",
      severity: "low",
      pkg: ctx.pkg,
      message:
        "no registry signatures or build provenance attestations available for this package version",
    });
  } else if (!ctx.hasAttestations) {
    out.push({
      ruleId: "WG-PROVENANCE-NO-ATTESTATION",
      severity: "low",
      pkg: ctx.pkg,
      message:
        "registry signature present, but no build provenance attestation (npm publish --provenance) is recorded",
    });
  }
  return out;
}
