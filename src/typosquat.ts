import type { Finding } from "./types";
import { editDistance } from "./distance";
import { TOP_NAMES } from "./top-names";

/** Flag dependency names that are 1-2 edits from a popular package name (likely typosquats). */
export function typosquatFindings(names: string[], popular: string[] = TOP_NAMES, maxDist = 2): Finding[] {
  const popSet = new Set(popular);
  const out: Finding[] = [];
  for (const name of names) {
    if (popSet.has(name)) continue; // exact match is the real package
    let best: { p: string; d: number } | null = null;
    for (const p of popular) {
      if (Math.abs(p.length - name.length) > maxDist) continue;
      const d = editDistance(name, p);
      if (d >= 1 && d <= maxDist && (!best || d < best.d)) best = { p, d };
      if (best && best.d === 1) break;
    }
    if (best) {
      out.push({
        ruleId: "WG-TYPOSQUAT",
        severity: best.d === 1 ? "high" : "medium",
        pkg: name,
        message: `name is ${best.d} edit(s) from popular package "${best.p}"`,
      });
    }
  }
  return out;
}
