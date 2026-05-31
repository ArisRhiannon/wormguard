// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// yarn berry (v2+) lockfile parser. The format is YAML-like but uses Yarn's
// own variant. We can parse it with the `yaml` package as long as we tolerate
// the `__metadata` block at the top.
//
// Each entry key is a colon-suffixed name@range string. Values carry:
//   version, resolution (e.g. "lodash@npm:4.17.21"), checksum, conditions.

import { parse as parseYaml } from "yaml";
import { type PackageRecord, WormguardError } from "../types";

interface BerryEntry {
  version?: string;
  resolution?: string;
  checksum?: string;
  conditions?: string;
  languageName?: string;
}

interface BerryLockfile {
  __metadata?: { version?: number; cacheKey?: string };
  [key: string]: BerryEntry | { version?: number; cacheKey?: string } | undefined;
}

const RESOLUTION_RE = /^([^@]+|@[^/]+\/[^@]+)@npm:(.+?)(?:::|$)/;

function parseResolution(resolution: string): { name: string; version: string } | null {
  const m = RESOLUTION_RE.exec(resolution);
  if (!m || !m[1] || !m[2]) return null;
  return { name: m[1], version: m[2] };
}

function defaultRegistryUrl(name: string, version: string): string {
  const safeName = name.replace("@", "").split("/").pop() ?? name;
  return `https://registry.npmjs.org/${name}/-/${safeName}-${version}.tgz`;
}

function hostOf(resolved: string | null): string | null {
  if (!resolved) return null;
  try {
    return new URL(resolved).host || null;
  } catch {
    return null;
  }
}

export function parseYarnBerryLockfile(text: string): PackageRecord[] {
  let json: BerryLockfile;
  try {
    json = parseYaml(text) as BerryLockfile;
  } catch (err) {
    throw new WormguardError(`invalid yarn berry lockfile: ${(err as Error).message}`);
  }
  if (!json || typeof json !== "object") throw new WormguardError("yarn berry lockfile is not an object");
  const out = new Map<string, PackageRecord>();
  for (const [key, raw] of Object.entries(json)) {
    if (key === "__metadata" || !raw || typeof raw !== "object") continue;
    const entry = raw as BerryEntry;
    if (typeof entry.resolution !== "string") continue;
    const nv = parseResolution(entry.resolution);
    if (!nv) continue;
    const cacheKey = `${nv.name}@${nv.version}`;
    if (out.has(cacheKey)) continue;
    const resolved = defaultRegistryUrl(nv.name, nv.version);
    out.set(cacheKey, {
      name: nv.name,
      version: nv.version,
      resolved,
      integrity: typeof entry.checksum === "string" ? entry.checksum : null,
      registryHost: hostOf(resolved),
      // Same as yarn classic: hasInstallScript filled in by node_modules walker.
      hasInstallScript: false,
      dev: false,
      packageManager: "yarn-berry",
    });
  }
  return [...out.values()];
}
