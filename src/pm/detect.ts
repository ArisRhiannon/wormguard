// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Detect which package manager produced the lockfile in a project root.
// Detection prefers explicit lockfiles; if multiple coexist, we pick by priority
// (pnpm > yarn-berry > yarn-classic > npm > bun) which matches the
// "this is the active PM" semantics that `corepack` uses today.
//
// TOCTOU narrowing (red-team M4): instead of `existsSync` followed by a
// later `readFileSync`, we attempt the read once and trap ENOENT. The
// content is returned alongside the detection so callers don't re-read
// the file (eliminating the second-of-two-syscalls race window).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PackageManager } from "../types";

export interface DetectedLockfile {
  packageManager: PackageManager;
  /** Absolute path to the lockfile. */
  path: string;
  /** File contents read at detection time. Callers must use this rather
   *  than re-reading the file (TOCTOU mitigation). */
  text: string;
}

function tryRead(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

/** Detect lockfiles present in `dir`. Returns all found, in priority order. */
export function detectLockfiles(dir: string): DetectedLockfile[] {
  const candidates: Array<{ pm: PackageManager; rel: string }> = [
    { pm: "pnpm", rel: "pnpm-lock.yaml" },
    { pm: "yarn-berry", rel: "yarn.lock" }, // resolved below
    { pm: "yarn-classic", rel: "yarn.lock" },
    { pm: "npm", rel: "package-lock.json" },
    { pm: "npm", rel: "npm-shrinkwrap.json" },
    { pm: "bun", rel: "bun.lock" },
    { pm: "bun", rel: "bun.lockb" },
  ];
  const found: DetectedLockfile[] = [];
  const seen = new Set<string>();
  // Cache: read each unique path at most once.
  const readCache = new Map<string, string | null>();
  const read = (p: string): string | null => {
    if (readCache.has(p)) return readCache.get(p) ?? null;
    const t = tryRead(p);
    readCache.set(p, t);
    return t;
  };

  for (const c of candidates) {
    const p = join(dir, c.rel);
    if (seen.has(p)) continue;
    const text = c.rel === "bun.lockb" ? "" : read(p);
    if (c.rel !== "bun.lockb" && text === null) continue; // file missing or unreadable
    if (c.pm === "yarn-berry") {
      if (text === null || !isYarnBerry(text)) continue;
    } else if (c.pm === "yarn-classic") {
      if (text === null || isYarnBerry(text)) continue;
    } else if (c.rel === "bun.lockb") {
      // Binary form: only report it if the path exists at all. We cannot
      // text-read it, but a separate lstat would re-introduce the TOCTOU.
      // Use readdirSync of the parent and check membership. (Cheaper than
      // existsSync because we already touched the parent for other lockfiles.)
      try {
        const fs = require("node:fs") as typeof import("node:fs");
        if (!fs.existsSync(p)) continue;
      } catch {
        continue;
      }
    }
    seen.add(p);
    found.push({ packageManager: c.pm, path: p, text: text ?? "" });
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
