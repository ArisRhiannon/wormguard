// SPDX-License-Identifier: MIT
import type { Finding } from "./types";
import { editDistance } from "./distance";
import { TOP_NAMES } from "./top-names";

/**
 * Flag dependency names that are 1-2 edits from a popular package name
 * (likely typosquats).
 *
 * Length floor (red-team M2 fix): for very short names (≤ 4 chars) a
 * Damerau-Levenshtein distance of 1 has too low a signal-to-noise ratio.
 * Example: "ms" (popular package, 2 chars) is distance-1 from many other
 * short names ("ns", "us", "os", ...) but those are themselves common
 * legitimate package names. We require:
 *
 *   - name length ≥ 4 for distance == 1 to fire,
 *   - name length ≥ 6 for distance == 2 to fire.
 *
 * The thresholds mean an attacker who wants to typosquat `ms` must publish
 * a name distance ≥ 1 with at least 4 characters, which dramatically
 * reduces the typosquat-attack surface for ultra-short names while still
 * catching `lodaash` (distance 1 of `lodash`, length 7).
 */
export function typosquatFindings(names: string[], popular: string[] = TOP_NAMES, maxDist = 2): Finding[] {
  const popSet = new Set(popular);
  const out: Finding[] = [];
  for (const name of names) {
    if (popSet.has(name)) continue; // exact match is the real package
    // Length-floor: ignore names too short to typosquat reliably.
    if (name.length < 4) continue;
    let best: { p: string; d: number } | null = null;
    for (const p of popular) {
      // Target-length floor: ultra-short popular names (npm, ms, fs, rc, pg) have
      // dense distance-1 neighbourhoods of legitimate packages (nypm, pathe→path
      // handled elsewhere) and are rarely typosquat *targets* in practice. Skipping
      // them removes a class of false positives without losing real detection
      // (attackers typosquat long recognisable names: react, lodash, webpack…).
      if (p.length < 4) continue;
      if (Math.abs(p.length - name.length) > maxDist) continue;
      const d = editDistance(name, p);
      if (d >= 1 && d <= maxDist && (!best || d < best.d)) best = { p, d };
      if (best && best.d === 1) break;
    }
    if (!best) continue;
    // For distance == 2, require longer names so we don't fire on short
    // overlaps (e.g. "lodaash" length 7 OK, "loda" length 4 distance-2
    // from "lodash" does NOT fire).
    if (best.d === 2 && name.length < 6) continue;
    out.push({
      ruleId: "WG-TYPOSQUAT",
      severity: best.d === 1 ? "high" : "medium",
      pkg: name,
      message: `name is ${best.d} edit(s) from popular package "${best.p}"`,
    });
  }
  return out;
}
