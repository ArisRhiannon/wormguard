// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Script-fingerprint allowlist.
//
// The single most effective false-positive reducer for an install-script
// auditor is to recognize the *exact bytes* of known-good lifecycle scripts
// and allow them, while flagging *any deviation* from those bytes for
// packages that normally have a stable script.
//
// This implements exactly that mechanism, addressing critique #3:
// "WG-CHILD-PROCESS marks node-sass / esbuild / sharp / prisma / bcrypt as
// high — you'll have an interminable exception list".
//
// Mechanics:
//
//   For each package in the bundled allowlist (data/script-allowlist.json):
//
//     - If the package's lifecycle script bytes hash to a known-good sha256,
//       ALL findings on that package's lifecycle scripts are SUPPRESSED
//       (we still keep the WG-INSTALL-SCRIPT advisory at low for inventory).
//
//     - If the package is in the allowlist but its script hash does NOT
//       match any known-good fingerprint, we emit a CRITICAL finding
//       WG-SCRIPT-FINGERPRINT-DRIFT — this is exactly the worm-injection
//       pattern: a previously-trusted package whose install script was
//       modified.
//
//   Packages NOT in the allowlist are scored normally by the rule engine
//   (they may still be flagged by AST hits, IoC matches, etc.).
//
// The allowlist is bundled but extensible by the user via .wormguard.json:
//   {
//     "scriptFingerprints": {
//       "esbuild": [
//         "sha256-of-known-good-postinstall-1",
//         "sha256-of-known-good-postinstall-2"
//       ]
//     }
//   }

import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Finding } from "../types";

interface AllowlistFile {
  version: number;
  /** Map of package name -> array of accepted lifecycle script body sha256 hex strings. */
  packages: Record<string, string[]>;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const ALLOWLIST_PATH = join(HERE, "..", "..", "data", "script-allowlist.json");

interface PreparedAllowlist {
  /** name -> Set of accepted sha256 (lowercase hex). */
  packages: Map<string, Set<string>>;
  /** Names in the allowlist (for fast membership). */
  names: Set<string>;
}

let cached: PreparedAllowlist | null = null;

function emptyAllowlist(): PreparedAllowlist {
  return { packages: new Map(), names: new Set() };
}

function loadAllowlist(): PreparedAllowlist {
  if (cached) return cached;
  if (!existsSync(ALLOWLIST_PATH)) {
    cached = emptyAllowlist();
    return cached;
  }
  let json: AllowlistFile;
  try {
    json = JSON.parse(readFileSync(ALLOWLIST_PATH, "utf8")) as AllowlistFile;
  } catch {
    cached = emptyAllowlist();
    return cached;
  }
  const packages = new Map<string, Set<string>>();
  const names = new Set<string>();
  if (json.packages && typeof json.packages === "object") {
    for (const [name, hashes] of Object.entries(json.packages)) {
      if (!Array.isArray(hashes)) continue;
      const set = new Set<string>(hashes.map((h) => String(h).toLowerCase()));
      packages.set(name, set);
      names.add(name);
    }
  }
  cached = { packages, names };
  return cached;
}

/** Reset cache (tests). */
export function resetAllowlistCache(): void {
  cached = null;
}

/** Compute sha256 hex of a script body. */
export function scriptSha256(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

/** True iff `name` is in the bundled allowlist (regardless of hash match). */
export function isAllowlistedPackage(name: string, userExtra?: Record<string, string[]>): boolean {
  const a = loadAllowlist();
  if (a.names.has(name)) return true;
  if (userExtra && Object.prototype.hasOwnProperty.call(userExtra, name)) return true;
  return false;
}

export interface FingerprintCheck {
  /** "match" — script hash is in allowlist; suppress findings.
   *  "drift" — package is in allowlist but hash differs; ESCALATE.
   *  "unknown" — package not in allowlist; pass through to other rules. */
  status: "match" | "drift" | "unknown";
  /** sha256 of the script body that was hashed. */
  sha256: string;
}

/** Check a single lifecycle-script body against the allowlist for `pkgName`. */
export function checkFingerprint(
  pkgName: string,
  scriptBody: string,
  userExtra?: Record<string, string[]>,
): FingerprintCheck {
  const a = loadAllowlist();
  const sha = scriptSha256(scriptBody);
  const accepted = new Set<string>();
  const fromBundle = a.packages.get(pkgName);
  if (fromBundle) for (const h of fromBundle) accepted.add(h);
  if (userExtra && Array.isArray(userExtra[pkgName])) {
    for (const h of userExtra[pkgName] as string[]) accepted.add(h.toLowerCase());
  }
  if (accepted.size === 0) return { status: "unknown", sha256: sha };
  if (accepted.has(sha)) return { status: "match", sha256: sha };
  return { status: "drift", sha256: sha };
}

/** Build a single finding describing a fingerprint drift on a known-good package.
 *  This is the *worm signature* in compact form: known package + unknown hash. */
export function fingerprintDriftFinding(pkgName: string, sha256: string, lifecycle: string): Finding {
  return {
    ruleId: "WG-SCRIPT-FINGERPRINT-DRIFT",
    severity: "critical",
    pkg: pkgName,
    message: `${lifecycle} script body hash ${sha256.slice(0, 12)}… does not match any known-good fingerprint for "${pkgName}"; the package is in the curated allowlist but its install script was modified — this is the worm-injection signature`,
  };
}
