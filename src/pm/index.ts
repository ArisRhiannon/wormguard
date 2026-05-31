// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Unified inventory loader. Picks the right parser by detected lockfile and
// returns a normalized PackageRecord[] regardless of which package manager
// produced the lockfile. The original npm parser is retained for backward
// compatibility.

import { readFileSync } from "node:fs";
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

/** Load inventory from `dir`, picking the right parser per detected lockfile. */
export function inventoryFromLockfiles(dir: string): InventoryResult {
  const found = detectLockfiles(dir);
  const all = new Map<string, PackageRecord>();
  const used: InventoryResult["lockfilesUsed"] = [];
  for (const f of found) {
    let recs: PackageRecord[] = [];
    try {
      const text = readFileSync(f.path, "utf8");
      switch (f.packageManager) {
        case "npm":
          recs = parseNpm(text);
          break;
        case "pnpm":
          recs = parsePnpmLockfile(text);
          break;
        case "yarn-classic":
          recs = parseYarnClassicLockfile(text);
          break;
        case "yarn-berry":
          recs = parseYarnBerryLockfile(text);
          break;
        case "bun":
          recs = parseBunLockfile(text, f.path.endsWith(".lockb"));
          break;
      }
    } catch {
      // Bad lockfile — record we tried and move on.
      continue;
    }
    used.push({ packageManager: f.packageManager, path: f.path });
    for (const r of recs) {
      const k = `${r.name}@${r.version}`;
      // First lockfile wins (priority order from detectLockfiles).
      if (!all.has(k)) all.set(k, r);
    }
  }
  return { records: [...all.values()], lockfilesUsed: used };
}
