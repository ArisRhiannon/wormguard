// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Detect whether the project has an install-time PREVENTION layer
// configured. wormguard itself is a detector — it reports findings, it
// does not block scripts. A complete defense in depth requires a
// prevention layer too:
//
//   * `@lavamoat/allow-scripts` (recommended: package-manager-agnostic
//     allowlist of which packages may run lifecycle scripts), OR
//   * `ignore-scripts=true` in `.npmrc` / npmrc.json (npm), OR
//   * `enableScripts: false` in `.yarnrc.yml` (yarn berry), OR
//   * trust-policies plugin / equivalent in pnpm config.
//
// If the project has a lockfile (so it actually installs deps) but none
// of the above are configured, we emit `WG-NO-PREVENTION-LAYER` (low) so
// the operator knows wormguard alone is detection-only.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./types";

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  lavamoat?: { allowScripts?: Record<string, boolean> };
  pnpm?: { onlyBuiltDependencies?: string[]; ignoredBuiltDependencies?: string[] };
}

function readPackageJson(dir: string): PackageJson | null {
  const p = join(dir, "package.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as PackageJson;
  } catch {
    return null;
  }
}

function hasNpmIgnoreScripts(dir: string): boolean {
  for (const rel of [".npmrc", "npmrc.json"]) {
    const p = join(dir, rel);
    if (!existsSync(p)) continue;
    try {
      const text = readFileSync(p, "utf8");
      // .npmrc is INI-ish: `ignore-scripts=true` (case-insensitive, optional whitespace)
      if (/^\s*ignore[-_]?scripts\s*=\s*true\s*$/im.test(text)) return true;
    } catch {
      /* fall through */
    }
  }
  return false;
}

function hasYarnDisabledScripts(dir: string): boolean {
  const p = join(dir, ".yarnrc.yml");
  if (!existsSync(p)) return false;
  try {
    const text = readFileSync(p, "utf8");
    // yarn berry: `enableScripts: false`
    return /^\s*enableScripts\s*:\s*false\s*$/im.test(text);
  } catch {
    return false;
  }
}

function hasLavamoat(pj: PackageJson | null): boolean {
  if (!pj) return false;
  const deps = { ...(pj.dependencies ?? {}), ...(pj.devDependencies ?? {}) };
  if ("@lavamoat/allow-scripts" in deps) return true;
  if (pj.lavamoat && typeof pj.lavamoat.allowScripts === "object") return true;
  return false;
}

function hasPnpmTrust(pj: PackageJson | null): boolean {
  if (!pj || !pj.pnpm) return false;
  // pnpm v8+ supports onlyBuiltDependencies as an explicit allowlist; its
  // mere presence is evidence the operator opted into prevention. (Empty
  // list is still allowlist-mode-on.)
  return Array.isArray(pj.pnpm.onlyBuiltDependencies);
}

export interface PreventionLayerResult {
  finding: Finding | null;
  layers: { lavamoat: boolean; npmIgnoreScripts: boolean; yarnDisabled: boolean; pnpmTrust: boolean };
}

/** Return WG-NO-PREVENTION-LAYER (low) if no prevention layer is configured
 *  in the project. Returns null when at least one is detected. The result
 *  also exposes the individual layer flags for the report header. */
export function preventionLayerCheck(dir: string, hasLockfile: boolean): PreventionLayerResult {
  if (!hasLockfile) return { finding: null, layers: { lavamoat: false, npmIgnoreScripts: false, yarnDisabled: false, pnpmTrust: false } };
  const pj = readPackageJson(dir);
  const layers = {
    lavamoat: hasLavamoat(pj),
    npmIgnoreScripts: hasNpmIgnoreScripts(dir),
    yarnDisabled: hasYarnDisabledScripts(dir),
    pnpmTrust: hasPnpmTrust(pj),
  };
  if (layers.lavamoat || layers.npmIgnoreScripts || layers.yarnDisabled || layers.pnpmTrust) {
    return { finding: null, layers };
  }
  return {
    finding: {
      ruleId: "WG-NO-PREVENTION-LAYER",
      severity: "low",
      pkg: "<project>",
      message:
        "no install-time prevention layer detected. wormguard reports findings; to actually BLOCK malicious scripts you also need one of: @lavamoat/allow-scripts, `ignore-scripts=true` in .npmrc, `enableScripts: false` in .yarnrc.yml, or pnpm `onlyBuiltDependencies`. Defense in depth requires both detection (wormguard) AND prevention.",
    },
    layers,
  };
}
