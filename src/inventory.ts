// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Inventory walker — locates every installed package's `package.json` across
// the layouts produced by npm, pnpm, yarn classic, and yarn berry (with
// `nodeLinker: node-modules`). Each layout has its own indirection:
//
//   npm / yarn-classic / yarn-berry-node-modules:
//     <root>/node_modules/<name>/package.json
//     <root>/node_modules/@scope/<name>/package.json
//     <root>/node_modules/<a>/node_modules/<b>/package.json   (nested)
//
//   pnpm:
//     <root>/node_modules/<name>            -> symlink
//     <root>/node_modules/@scope/<name>     -> symlink
//     <root>/node_modules/.pnpm/<id>/node_modules/<name>/package.json   (real files)
//     <root>/node_modules/.pnpm/<id>/node_modules/@scope/<name>/package.json
//
// We follow symlinks (so pnpm's flat surface still resolves), AND we also
// walk `<root>/node_modules/.pnpm/*/node_modules/*` directly to catch the
// hoisted-by-id store entries. We dedupe by absolute resolved path so a
// package symlinked into multiple consumer trees is counted once.
//
// We also do limited bounded-depth nested traversal so a misbehaving
// `node_modules/<a>/node_modules/<b>` (npm v2 style or shrinkwrap nested)
// is reachable.

import { readdirSync, readFileSync, existsSync, realpathSync, statSync, lstatSync } from "node:fs";
import { join, basename, resolve } from "node:path";
import type { LifecycleScripts } from "./types";

export interface InstalledPackage {
  name: string;
  /** Real (resolved) directory of the package. */
  dir: string;
  scripts: LifecycleScripts;
  /** Layout the package was found through (for the report). */
  layout: "npm" | "pnpm-store" | "pnpm-link" | "nested";
}

const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare"] as const;

function readScripts(dir: string): { name: string; scripts: LifecycleScripts } | null {
  const pj = join(dir, "package.json");
  if (!existsSync(pj)) return null;
  let json: { name?: unknown; scripts?: Record<string, unknown> };
  try {
    json = JSON.parse(readFileSync(pj, "utf8"));
  } catch {
    return null;
  }
  const s = json.scripts ?? {};
  const scripts: LifecycleScripts = {};
  for (const k of LIFECYCLE) {
    const v = s[k];
    if (typeof v === "string") scripts[k] = v;
  }
  const name = typeof json.name === "string" ? json.name : basename(dir);
  return { name, scripts };
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function resolveReal(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isSymlink(p: string): boolean {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

interface Visit {
  dir: string;
  layout: InstalledPackage["layout"];
}

/** Collect candidate directories. Each candidate is the *real* path of a
 *  package directory containing a package.json. */
function collectDirs(root: string): Visit[] {
  const out: Visit[] = [];
  const nm = join(root, "node_modules");
  if (!existsSync(nm)) return out;

  const seen = new Set<string>();
  const visit = (dir: string, layout: InstalledPackage["layout"], depth: number): void => {
    if (depth > 6) return; // bounded recursion
    const real = resolveReal(dir);
    if (!real) return;
    if (seen.has(real)) return;
    seen.add(real);
    if (!isDir(real)) return;
    const pj = join(real, "package.json");
    if (existsSync(pj)) out.push({ dir: real, layout });
    // Recurse into nested node_modules (npm v2-style / shrinkwrap).
    const nested = join(real, "node_modules");
    if (existsSync(nested)) walkSurface(nested, "nested", depth + 1);
  };

  const walkSurface = (surface: string, layout: InstalledPackage["layout"], depth: number): void => {
    for (const entry of safeReaddir(surface)) {
      if (entry.startsWith(".")) continue; // skip .bin, .package-lock.json, .pnpm
      const full = join(surface, entry);
      if (entry.startsWith("@")) {
        for (const sub of safeReaddir(full)) {
          if (sub.startsWith(".")) continue;
          const subLayout = isSymlink(join(full, sub)) ? "pnpm-link" : layout;
          visit(join(full, sub), subLayout, depth);
        }
      } else {
        const subLayout = isSymlink(full) ? "pnpm-link" : layout;
        visit(full, subLayout, depth);
      }
    }
  };

  walkSurface(nm, "npm", 0);

  // pnpm store: <root>/node_modules/.pnpm/<id>/node_modules/<pkg>
  const pnpmStore = join(nm, ".pnpm");
  if (existsSync(pnpmStore)) {
    for (const id of safeReaddir(pnpmStore)) {
      if (id.startsWith(".")) continue;
      const inner = join(pnpmStore, id, "node_modules");
      if (!existsSync(inner)) continue;
      walkSurface(inner, "pnpm-store", 0);
    }
  }

  return out;
}

/** Scan `<root>/node_modules` (and `.pnpm/`) for installed packages. */
export function scanNodeModules(root: string): InstalledPackage[] {
  const visits = collectDirs(resolve(root));
  const out: InstalledPackage[] = [];
  for (const v of visits) {
    const meta = readScripts(v.dir);
    if (!meta) continue;
    out.push({ name: meta.name, dir: v.dir, scripts: meta.scripts, layout: v.layout });
  }
  // Final dedupe by name+real-dir so we do not report the same package twice
  // when it is reachable via both the symlinked surface and the .pnpm store.
  const seenKey = new Set<string>();
  const dedup: InstalledPackage[] = [];
  for (const p of out) {
    const k = `${p.name}|${p.dir}`;
    if (seenKey.has(k)) continue;
    seenKey.add(k);
    dedup.push(p);
  }
  return dedup;
}
