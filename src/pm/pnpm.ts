// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// pnpm lockfile parser. Format reference:
//   https://github.com/pnpm/pnpm/blob/main/lockfile/lockfile-types/src/index.ts
//
// pnpm-lock.yaml carries:
//   lockfileVersion (string, e.g. "9.0", "6.0")
//   importers / packages / snapshots blocks
//
// Each `packages.<key>` is keyed by either:
//   /<name>@<version>            (v6 and earlier)
//   <name>@<version>             (v7+)
//   /<name>@<version>(peer)      (peer-aware)
//
// We extract: name, version, resolved (we synthesize the npm registry URL when
// `resolution.tarball` is absent), integrity, hasInstallScript (from the
// `requiresBuild: true` flag pnpm sets when a package has lifecycle scripts),
// dev (from `dev: true`).

import { parse as parseYaml } from "yaml";
import { type PackageRecord, WormguardError } from "../types";

interface PnpmPackageEntry {
  resolution?: { tarball?: string; integrity?: string; commit?: string; type?: string };
  dev?: boolean;
  optional?: boolean;
  requiresBuild?: boolean;
  hasInstallScript?: boolean;
  name?: string;
  version?: string;
}

interface PnpmLockfile {
  lockfileVersion?: string | number;
  packages?: Record<string, PnpmPackageEntry>;
  snapshots?: Record<string, PnpmPackageEntry>;
}

const NAME_VERSION_RE = /^\/?(@[^/]+\/[^@()]+|[^/@()]+)@([^()]+?)(?:\(.*\))?$/;

function hostOf(resolved: string | null): string | null {
  if (!resolved) return null;
  try {
    return new URL(resolved).host || null;
  } catch {
    return null;
  }
}

function nameVersion(key: string): { name: string; version: string } | null {
  const m = NAME_VERSION_RE.exec(key);
  if (!m || !m[1] || !m[2]) return null;
  return { name: m[1], version: m[2] };
}

function defaultRegistryUrl(name: string, version: string): string {
  // pnpm omits the tarball URL when it can be derived deterministically from
  // the registry (which is always npmjs unless `.npmrc` says otherwise; for
  // forensic purposes this synthesized URL is good enough — it's only used for
  // host extraction and audit display).
  const safeName = name.replace("@", "").split("/").pop() ?? name;
  return `https://registry.npmjs.org/${name}/-/${safeName}-${version}.tgz`;
}

export function parsePnpmLockfile(text: string): PackageRecord[] {
  let json: PnpmLockfile;
  try {
    json = parseYaml(text) as PnpmLockfile;
  } catch (err) {
    throw new WormguardError(`invalid pnpm lockfile YAML: ${(err as Error).message}`);
  }
  if (!json || typeof json !== "object") throw new WormguardError("pnpm lockfile is not an object");
  const out: PackageRecord[] = [];
  // pnpm v9 splits metadata between `packages` (resolution-only) and `snapshots`
  // (dev/optional/requiresBuild flags). Earlier versions keep it in `packages`.
  const sources: Record<string, PnpmPackageEntry>[] = [];
  if (json.packages && typeof json.packages === "object") sources.push(json.packages);
  if (json.snapshots && typeof json.snapshots === "object") sources.push(json.snapshots);

  // Merge metadata across packages + snapshots before emitting (pnpm v9
  // splits resolution/integrity into `packages` and dev/requiresBuild into
  // `snapshots`, keyed identically).
  const merged = new Map<string, { nv: { name: string; version: string }; entry: PnpmPackageEntry }>();
  for (const block of sources) {
    for (const [key, entry] of Object.entries(block)) {
      if (!entry || typeof entry !== "object") continue;
      const nv = nameVersion(key);
      if (!nv) continue;
      const k = `${nv.name}@${nv.version}`;
      const prev = merged.get(k);
      if (prev) {
        prev.entry = {
          ...prev.entry,
          ...entry,
          resolution: { ...(prev.entry.resolution ?? {}), ...(entry.resolution ?? {}) },
        };
      } else {
        merged.set(k, { nv, entry: { ...entry, resolution: { ...(entry.resolution ?? {}) } } });
      }
    }
  }

  for (const { nv, entry } of merged.values()) {
    const tarball = entry.resolution?.tarball ?? null;
    const resolved = tarball ?? defaultRegistryUrl(nv.name, nv.version);
    const integrity =
      typeof entry.resolution?.integrity === "string" ? entry.resolution.integrity : null;
    out.push({
      name: nv.name,
      version: nv.version,
      resolved,
      integrity,
      registryHost: hostOf(resolved),
      hasInstallScript: entry.requiresBuild === true || entry.hasInstallScript === true,
      dev: entry.dev === true,
      packageManager: "pnpm",
    });
  }
  return out;
}
