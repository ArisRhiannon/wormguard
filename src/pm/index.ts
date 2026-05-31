// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Unified inventory loader. Picks the right parser by detected lockfile and
// returns a normalized PackageRecord[] regardless of which package manager
// produced the lockfile. The original npm parser is retained for backward
// compatibility.

import { type PackageRecord } from "../types";
import { detectLockfiles } from "./detect";
import { parseLockfile as parseNpm } from "../lockfile";
import { parsePnpmLockfile } from "./pnpm";
import { parseYarnClassicLockfile } from "./yarn-classic";
import { parseYarnBerryLockfile } from "./yarn-berry";
import { parseBunLockfile } from "./bun";

export interface InventoryResult {
  records: PackageRecord[];
  lockfilesUsed: Array<{ packageManager: string; path: string }>;
}

/** Load inventory from `dir`, picking the right parser per detected lockfile.
 *  TOCTOU-narrow: we use the text returned by detectLockfiles, not a re-read. */
export function inventoryFromLockfiles(dir: string): InventoryResult {
  const found = detectLockfiles(dir);
  const all = new Map<string, PackageRecord>();
  const used: InventoryResult["lockfilesUsed"] = [];
  for (const f of found) {
    let recs: PackageRecord[] = [];
    try {
      switch (f.packageManager) {
        case "npm":
          recs = parseNpm(f.text);
          break;
        case "pnpm":
          recs = parsePnpmLockfile(f.text);
          break;
        case "yarn-classic":
          recs = parseYarnClassicLockfile(f.text);
          break;
        case "yarn-berry":
          recs = parseYarnBerryLockfile(f.text);
          break;
        case "bun":
          recs = parseBunLockfile(f.text, f.path.endsWith(".lockb"));
          break;
      }
    } catch {
      continue;
    }
    used.push({ packageManager: f.packageManager, path: f.path });
    for (const r of recs) {
      const k = `${r.name}@${r.version}`;
      if (!all.has(k)) all.set(k, r);
    }
  }
  return { records: [...all.values()], lockfilesUsed: used };
}
