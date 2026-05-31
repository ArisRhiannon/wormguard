// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Indicator-of-Compromise matcher (v2: version-range aware).
//
// Loads `data/iocs.json` (built by scripts/refresh-corpus.ts from the
// public GitHub Advisory Database `type=malware` feed) and exposes:
//
//   matchPackageName(name, version?)
//     - if `version` is supplied AND the corpus has at least one concrete
//       SemVer range for the package, only fires WG-IOC-NAME when the
//       supplied version satisfies one of the affected ranges. This is
//       the fix for the false-positive on legitimately-recovered
//       packages (red-team finding C2): ansi-regex@6.2.1 was malicious;
//       ansi-regex@6.3.0 is clean. The previous schema flagged the
//       whole package permanently.
//     - if `version` is NOT supplied, falls back to name-only match
//       (legacy v1 behavior, only safe for callers that have already
//       reasoned about ranges).
//
// All version comparisons are delegated to the `semver` package
// (the same one npm uses internally).

import { readFileSync, existsSync } from "node:fs";
import semver from "semver";
import type { Finding } from "../types";
import { resolveDataPath } from "../data-path";

interface IocCorpusV1 {
  version: 1;
  fetchedAt?: string;
  names?: string[];
  scriptSha256?: string[];
  domains?: string[];
  wallets?: string[];
}
interface IocCorpusV2 {
  version: 2;
  fetchedAt?: string;
  names?: string[];
  ranges?: Record<string, string[]>;
  scriptSha256?: string[];
  domains?: string[];
  wallets?: string[];
}
type IocCorpus = IocCorpusV1 | IocCorpusV2;

const CORPUS_PATH = resolveDataPath(import.meta.url, "iocs.json");

interface PreparedCorpus {
  /** Lowercased package names present in the corpus. Used for membership. */
  names: Set<string>;
  /** Lowercased package name -> array of vulnerable_version_range strings. */
  ranges: Map<string, string[]>;
  scriptSha256: Set<string>;
  domains: string[];
  wallets: Set<string>;
  fetchedAt: string;
  size: number;
}

let cached: PreparedCorpus | null = null;

function emptyCorpus(): PreparedCorpus {
  return {
    names: new Set(),
    ranges: new Map(),
    scriptSha256: new Set(),
    domains: [],
    wallets: new Set(),
    fetchedAt: "",
    size: 0,
  };
}

function loadCorpus(): PreparedCorpus {
  if (cached) return cached;
  if (!existsSync(CORPUS_PATH)) {
    cached = emptyCorpus();
    return cached;
  }
  let json: IocCorpus;
  try {
    json = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as IocCorpus;
  } catch {
    cached = emptyCorpus();
    return cached;
  }
  const names = new Set<string>(Array.isArray(json.names) ? json.names.map((n) => n.toLowerCase()) : []);
  const ranges = new Map<string, string[]>();
  if (json.version === 2 && json.ranges && typeof json.ranges === "object") {
    for (const [name, arr] of Object.entries(json.ranges)) {
      if (!Array.isArray(arr)) continue;
      const lc = name.toLowerCase();
      ranges.set(lc, arr.filter((s): s is string => typeof s === "string"));
      names.add(lc);
    }
  }
  cached = {
    names,
    ranges,
    scriptSha256: new Set(
      Array.isArray(json.scriptSha256) ? json.scriptSha256.map((h) => h.toLowerCase()) : [],
    ),
    domains: Array.isArray(json.domains) ? [...json.domains].sort((a, b) => b.length - a.length) : [],
    wallets: new Set(Array.isArray(json.wallets) ? json.wallets : []),
    fetchedAt: typeof json.fetchedAt === "string" ? json.fetchedAt : "",
    size: names.size,
  };
  return cached;
}

/** Reset cache (for tests). */
export function resetCorpusCache(): void {
  cached = null;
}

/** Return summary metadata about the loaded corpus. */
export function corpusStats(): { fetchedAt: string; size: number; rangedCount: number } {
  const c = loadCorpus();
  return { fetchedAt: c.fetchedAt, size: c.size, rangedCount: c.ranges.size };
}

/**
 * Test whether a given version is inside any of `ranges`. We support:
 *   - SemVer range strings like "= 1.2.3", ">= 0", ">=1.0.0 <2.0.0"
 *     (semver.satisfies handles these directly).
 *   - The catch-all ">= 0" is treated as "no narrower information"; we
 *     don't fire a critical finding on its sole basis.
 */
function versionInsideRanges(version: string, ranges: string[]): {
  inside: boolean;
  matchedRange: string | null;
  onlyCatchAll: boolean;
} {
  const v = semver.valid(version) ?? semver.valid(semver.coerce(version) ?? "");
  if (!v) {
    // We can't compare; do not claim a hit on an unparseable version. Fall
    // back to "uncertain" so the caller can downgrade the finding instead
    // of emitting a critical false positive.
    return { inside: false, matchedRange: null, onlyCatchAll: false };
  }
  const concrete = ranges.filter((r) => r.replace(/\s+/g, "") !== ">=0");
  const onlyCatchAll = concrete.length === 0 && ranges.length > 0;
  for (const range of concrete) {
    try {
      if (semver.satisfies(v, range, { includePrerelease: true })) {
        return { inside: true, matchedRange: range, onlyCatchAll: false };
      }
    } catch {
      /* skip unparseable range */
    }
  }
  return { inside: false, matchedRange: null, onlyCatchAll };
}

/**
 * Match an npm package name (and optionally version) against the IoC corpus.
 *
 * Behavior:
 *
 * - If `version` is supplied and the corpus has at least one concrete
 *   range for `name`, fire `WG-IOC-NAME` (critical) ONLY when the version
 *   intersects one of those ranges. Versions outside any concrete range
 *   yield null (not a false positive).
 * - If the corpus has only the catch-all ">= 0" range for `name`, OR no
 *   range at all, AND a version was supplied, fire `WG-IOC-NAME-LEGACY`
 *   (medium) instead — telling the operator the package was historically
 *   compromised but the corpus has no version information to confirm
 *   the installed version is affected.
 * - If `version` is NOT supplied, fall back to legacy v1 name-only match
 *   (medium severity, since we cannot rule out a since-recovered version).
 */
export function matchPackageName(name: string, version?: string): Finding | null {
  const c = loadCorpus();
  const lc = name.toLowerCase();
  if (!c.names.has(lc)) return null;
  const ranges = c.ranges.get(lc) ?? [];
  if (typeof version !== "string" || version.length === 0) {
    // No version info from the caller. Stay conservative.
    return {
      ruleId: "WG-IOC-NAME-LEGACY",
      severity: "medium",
      pkg: name,
      message:
        "package name appears in the GitHub Advisory Database malware list, but version information was not supplied by the lockfile (cannot verify installed version is the affected one)",
    };
  }
  const r = versionInsideRanges(version, ranges);
  if (r.inside) {
    return {
      ruleId: "WG-IOC-NAME",
      severity: "critical",
      pkg: name,
      message: `package version ${version} is in a confirmed-malicious range "${r.matchedRange}" from the GitHub Advisory Database (malware advisory)`,
    };
  }
  if (ranges.length === 0 || r.onlyCatchAll) {
    return {
      ruleId: "WG-IOC-NAME-LEGACY",
      severity: "medium",
      pkg: name,
      message: `package name appears in the GitHub Advisory Database malware list with only a catch-all range; installed version ${version} cannot be confirmed inside the affected window. Treat as historical advisory.`,
    };
  }
  return null;
}

/** Match a sha256 (lowercase hex) of a script body against the IoC corpus. */
export function matchScriptHash(name: string, sha256: string): Finding | null {
  const c = loadCorpus();
  if (c.scriptSha256.has(sha256.toLowerCase())) {
    return {
      ruleId: "WG-IOC-SCRIPT-HASH",
      severity: "critical",
      pkg: name,
      message: `lifecycle script body hash (${sha256.slice(0, 16)}…) matches a known-malicious script in the IoC corpus`,
    };
  }
  return null;
}

/** Find any IoC domains present in a free-form text blob (script source, etc). */
export function matchDomains(text: string): string[] {
  const c = loadCorpus();
  const out: string[] = [];
  const lower = text.toLowerCase();
  for (const d of c.domains) {
    if (lower.includes(d)) out.push(d);
  }
  return out;
}

/** Find any IoC wallet addresses in a free-form text blob. */
export function matchWallets(text: string): string[] {
  const c = loadCorpus();
  const out: string[] = [];
  for (const w of c.wallets) {
    if (text.includes(w)) out.push(w);
  }
  return out;
}
