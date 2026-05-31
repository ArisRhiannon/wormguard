// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Fuzzy IoC matching: catch typosquats *of confirmed-malicious package
// names*. The plain `matchPackageName` is exact-match; an attacker who
// publishes `lodaash` (versus the malicious `lodash-iife-prototype`) might
// not appear in the corpus directly, but a name within Damerau-Levenshtein
// distance 1 of an entry that *is* in the corpus is a strong signal.
//
// We deliberately do NOT fuzz against the entire corpus (23k names) for
// every project name on every scan — that would be O(N*M*L). Instead we:
//
//   1. Bucket malicious names by length (±1) into a Map<length, Set<name>>.
//   2. For each project name, only check buckets length-1 .. length+1.
//   3. For each candidate, compute distance and emit if distance == 1.
//
// At a typical project size (≤ a few hundred names) and corpus size of
// 23k this is ~hundreds of thousands of comparisons per scan, finishing
// in < 50ms in practice.

import { editDistance } from "../distance";
import { TOP_NAMES } from "../top-names";
import { readFileSync, existsSync } from "node:fs";
import { resolveDataPath } from "../data-path";
import type { Finding } from "../types";

const POPULAR = new Set(TOP_NAMES.map((n) => n.toLowerCase()));

const CORPUS_PATH = resolveDataPath(import.meta.url, "iocs.json");

let bucketed: Map<number, string[]> | null = null;
let exactSet: Set<string> | null = null;

function loadBuckets(): { bucketed: Map<number, string[]>; exactSet: Set<string> } {
  if (bucketed && exactSet) return { bucketed, exactSet };
  const buckets = new Map<number, string[]>();
  const exact = new Set<string>();
  if (!existsSync(CORPUS_PATH)) {
    bucketed = buckets;
    exactSet = exact;
    return { bucketed, exactSet };
  }
  try {
    const json = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as { names?: unknown };
    if (!Array.isArray(json.names)) {
      bucketed = buckets;
      exactSet = exact;
      return { bucketed, exactSet };
    }
    for (const raw of json.names) {
      if (typeof raw !== "string") continue;
      const lower = raw.toLowerCase();
      exact.add(lower);
      const arr = buckets.get(lower.length);
      if (arr) arr.push(lower);
      else buckets.set(lower.length, [lower]);
    }
  } catch {
    /* fall through with empty maps */
  }
  bucketed = buckets;
  exactSet = exact;
  return { bucketed, exactSet };
}

/** Reset cache (tests). */
export function resetIocFuzzyCache(): void {
  bucketed = null;
  exactSet = null;
}

/** For each project name, emit a finding if there's a malicious-corpus name
 *  within edit-distance 1 (and the project name is not itself in the corpus,
 *  which would already have been flagged by the exact matcher). */
export function iocFuzzyFindings(names: string[]): Finding[] {
  const { bucketed: buckets, exactSet: exact } = loadBuckets();
  if (exact.size === 0) return [];
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const raw of names) {
    const name = raw.toLowerCase();
    if (exact.has(name)) continue; // already covered by WG-IOC-NAME
    if (POPULAR.has(name)) continue; // legitimate popular package: typosquats targeting IT will be in the corpus, not the other way around.
    // Length floor (FP benchmark, docs/false-positive-baseline.md): in a 23k-name
    // corpus the distance-1 neighbourhood of a short name is dense, so legit short
    // packages (fdir, levn, etag, rc, ini, ...) collide with malicious entries.
    // Require ≥5 chars; the exact matcher (WG-IOC-NAME) still covers short names.
    if (name.length < 5) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const lens = [name.length - 1, name.length, name.length + 1];
    let bestNeighbor: string | null = null;
    for (const len of lens) {
      const bucket = buckets.get(len);
      if (!bucket) continue;
      for (const cand of bucket) {
        if (cand === name) continue;
        const d = editDistance(name, cand);
        if (d === 1) {
          bestNeighbor = cand;
          break;
        }
      }
      if (bestNeighbor) break;
    }
    if (bestNeighbor) {
      out.push({
        ruleId: "WG-IOC-NEAR",
        // medium, not high: this is a fuzzy proximity heuristic (name is *near*
        // a malicious name), not a confirmed indicator. The exact match
        // (WG-IOC-NAME) remains critical. Empirically (FP baseline) the
        // distance-1 neighbourhood still catches legit mid-tier packages
        // (color-support ~ colors-support), so this must not gate CI as high.
        severity: "medium",
        pkg: raw,
        message: `name is 1 edit from a confirmed-malicious npm package "${bestNeighbor}" (possible typosquat of a known-malicious package — verify this dependency is intentional)`,
      });
    }
  }
  return out;
}
