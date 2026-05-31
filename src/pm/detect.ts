// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Detect which package manager produced the lockfile in a project root.
// Detection prefers explicit lockfiles; if multiple coexist, we pick by priority
// (pnpm > yarn-berry > yarn-classic > npm > bun) which matches the
// "this is the active PM" semantics that `corepack` uses today.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { PackageManager } from "../types";

export interface DetectedLockfile {
  packageManager: PackageManager;
  /** Absolute path to the lockfile. */
  path: string;
}

/** Detect lockfiles present in `dir`. Returns all found, in priority order. */
export function detectLockfiles(dir: string): DetectedLockfile[] {
  const candidates: Array<{ pm: PackageManager; rel: string; needsCheck?: (text: string) => boolean }> = [
    { pm: "pnpm", rel: "pnpm-lock.yaml" },
    {
      pm: "yarn-berry",
      rel: "yarn.lock",
      needsCheck: isYarnBerry,
    },
    { pm: "yarn-classic", rel: "yarn.lock" },
    { pm: "npm", rel: "package-lock.json" },
    { pm: "npm", rel: "npm-shrinkwrap.json" },
    { pm: "bun", rel: "bun.lock" },
    { pm: "bun", rel: "bun.lockb" },
  ];
  const found: DetectedLockfile[] = [];
  const seen = new Set<string>();
  for (const c of candidates) {
    const p = join(dir, c.rel);
    if (!existsSync(p) || seen.has(p)) continue;
    if (c.needsCheck) {
      try {
        if (!c.needsCheck(readFileSync(p, "utf8"))) continue;
      } catch {
        continue;
      }
    } else if (c.pm === "yarn-classic" && existsSync(join(dir, "yarn.lock"))) {
      // If we already added yarn-berry above for the same yarn.lock, skip.
      try {
        if (isYarnBerry(readFileSync(p, "utf8"))) continue;
      } catch {
        /* fall through, treat as classic */
      }
    }
    seen.add(p);
    found.push({ packageManager: c.pm, path: p });
  }
  return found;
}

/**
 * yarn berry (v2+) lockfiles begin with a `__metadata:` block (YAML),
 * yarn classic begins with the comment `# yarn lockfile v1`.
 */
export function isYarnBerry(text: string): boolean {
  return /^\s*__metadata:\s*$/m.test(text) || /\n\s*version:\s*[2-9]\b/.test(text);
}
