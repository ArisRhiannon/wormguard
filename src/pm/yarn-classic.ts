// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// yarn classic (v1) lockfile parser. Uses @yarnpkg/lockfile, the official
// parser shipped by Yarn.
//
// Each top-level key is a name@range string (which can group multiple ranges).
// Values carry: version, resolved, integrity, dependencies.

import * as lockfile from "@yarnpkg/lockfile";
import { type PackageRecord, WormguardError } from "../types";

interface YarnEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function hostOf(resolved: string | null): string | null {
  if (!resolved) return null;
  // yarn resolves with a URL fragment after `#sha1`; strip it for parsing.
  const url = resolved.split("#")[0];
  try {
    return new URL(url ?? "").host || null;
  } catch {
    return null;
  }
}

function nameOfKey(key: string): string {
  // a key looks like "lodash@^4.0.0" or "@scope/pkg@^1.0.0" or "pkg@^1, pkg@^2"
  const first = key.split(",")[0]?.trim() ?? key;
  if (first.startsWith("@")) {
    const lastAt = first.lastIndexOf("@");
    return lastAt > 0 ? first.slice(0, lastAt) : first;
  }
  const at = first.indexOf("@");
  return at > 0 ? first.slice(0, at) : first;
}

export function parseYarnClassicLockfile(text: string): PackageRecord[] {
  const result = lockfile.parse(text);
  if (result.type !== "success" || !result.object) {
    throw new WormguardError(`invalid yarn.lock: ${result.type}`);
  }
  const out = new Map<string, PackageRecord>();
  for (const [key, raw] of Object.entries(result.object as Record<string, YarnEntry>)) {
    if (!raw || typeof raw !== "object") continue;
    const name = nameOfKey(key);
    const version = typeof raw.version === "string" ? raw.version : "";
    const cacheKey = `${name}@${version}`;
    if (out.has(cacheKey)) continue;
    const resolved = typeof raw.resolved === "string" ? raw.resolved.split("#")[0] ?? null : null;
    out.set(cacheKey, {
      name,
      version,
      resolved,
      integrity: typeof raw.integrity === "string" ? raw.integrity : null,
      registryHost: hostOf(resolved),
      // yarn classic doesn't record `hasInstallScript` in the lockfile; the
      // node_modules walker will fill that in when it encounters the package.
      hasInstallScript: false,
      dev: false,
      packageManager: "yarn-classic",
    });
  }
  return [...out.values()];
}
