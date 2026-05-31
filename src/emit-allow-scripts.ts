// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// `wormguard emit-allow-scripts [dir] [--out FILE]`
//
// Bridge from wormguard's bundled script-fingerprint allowlist to the
// configuration format used by `@lavamoat/allow-scripts`. The output is a
// JSON object suitable for embedding in `package.json` under the
// `lavamoat.allowScripts` key:
//
//   {
//     "esbuild": true,
//     "sharp": true,
//     "<unknown package with lifecycle script>": false
//   }
//
// Default-deny semantics: any package that has a lifecycle script and
// does NOT match a known-good fingerprint in our bundled allowlist OR
// any user-supplied fingerprint (via --config FILE) is set to `false`.
// Operators must opt in to anything we cannot prove safe.
//
// This is a one-shot helper, NOT a runtime integration. wormguard does
// not import from LavaMoat and LavaMoat does not import from wormguard;
// they coexist via this file format.

import type { InstalledPackage } from "./inventory";
import { checkFingerprint } from "./corpus/allowlist";

export interface EmitOptions {
  scriptFingerprints?: Record<string, string[]>;
}

export interface EmitResult {
  /** Map of package-name -> allow boolean, in stable name-sorted order. */
  allowScripts: Record<string, boolean>;
  /** Per-package decision rationale, useful for review. */
  rationale: Array<{ package: string; allow: boolean; reason: string }>;
}

/** Build a LavaMoat-compatible allowScripts map from an installed-package set. */
export function emitAllowScripts(installed: InstalledPackage[], opts: EmitOptions = {}): EmitResult {
  const allowScripts: Record<string, boolean> = {};
  const rationale: EmitResult["rationale"] = [];
  const seen = new Set<string>();

  for (const p of installed) {
    if (seen.has(p.name)) continue;
    seen.add(p.name);
    const lifecycleEntries = Object.entries(p.scripts).filter(([, v]) => typeof v === "string" && v.length > 0);
    if (lifecycleEntries.length === 0) continue; // no lifecycle script, no entry needed

    // For a package with multiple lifecycle scripts, ALL must match a known-good fingerprint.
    let allMatch = true;
    let inAllowlist = false;
    let reason = "";
    for (const [lifecycle, body] of lifecycleEntries) {
      const r = checkFingerprint(p.name, body as string, opts.scriptFingerprints);
      if (r.status === "match") {
        inAllowlist = true;
      } else if (r.status === "drift") {
        allMatch = false;
        inAllowlist = true;
        reason = `drift in ${lifecycle} (sha256 ${r.sha256.slice(0, 12)}…) — known-good package with unknown body, default DENY`;
      } else {
        allMatch = false;
        if (!reason) reason = `package not in bundled allowlist; default DENY`;
      }
    }

    if (allMatch && inAllowlist) {
      allowScripts[p.name] = true;
      rationale.push({ package: p.name, allow: true, reason: "all lifecycle script bodies match known-good fingerprints" });
    } else {
      allowScripts[p.name] = false;
      rationale.push({ package: p.name, allow: false, reason: reason || "default deny" });
    }
  }

  // Sort by package name for stable output.
  const sorted: Record<string, boolean> = {};
  for (const k of Object.keys(allowScripts).sort()) sorted[k] = allowScripts[k] as boolean;
  rationale.sort((a, b) => a.package.localeCompare(b.package));
  return { allowScripts: sorted, rationale };
}

/** Format the result as a JSON string suitable for embedding under
 *  `lavamoat.allowScripts` in package.json. */
export function emitAllowScriptsJson(result: EmitResult): string {
  return JSON.stringify(result.allowScripts, null, 2);
}
