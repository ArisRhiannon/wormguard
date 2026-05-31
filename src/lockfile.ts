import { type PackageRecord, WormguardError } from "./types";

function hostOf(resolved: string | null): string | null {
  if (!resolved) return null;
  try {
    return new URL(resolved).host || null;
  } catch {
    return null;
  }
}

function nameFromKey(key: string): string {
  const marker = "node_modules/";
  const i = key.lastIndexOf(marker);
  return i < 0 ? key : key.slice(i + marker.length);
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function fromPackages(packages: Record<string, any>): PackageRecord[] {
  const out = new Map<string, PackageRecord>();
  for (const [key, entry] of Object.entries(packages)) {
    if (key === "" || !key.includes("node_modules/") || !entry || typeof entry !== "object") continue;
    const name: string = typeof entry.name === "string" ? entry.name : nameFromKey(key);
    const version: string = typeof entry.version === "string" ? entry.version : "";
    const resolved: string | null = typeof entry.resolved === "string" ? entry.resolved : null;
    const rec: PackageRecord = {
      name,
      version,
      resolved,
      integrity: typeof entry.integrity === "string" ? entry.integrity : null,
      registryHost: hostOf(resolved),
      hasInstallScript: entry.hasInstallScript === true,
      dev: entry.dev === true,
    };
    out.set(`${name}@${version}`, rec);
  }
  return [...out.values()];
}

function fromDependencies(deps: Record<string, any>, out: Map<string, PackageRecord>): void {
  for (const [name, info] of Object.entries(deps)) {
    if (!info || typeof info !== "object") continue;
    const version: string = typeof info.version === "string" ? info.version : "";
    const resolved: string | null = typeof info.resolved === "string" ? info.resolved : null;
    out.set(`${name}@${version}`, {
      name,
      version,
      resolved,
      integrity: typeof info.integrity === "string" ? info.integrity : null,
      registryHost: hostOf(resolved),
      hasInstallScript: false, // not available in legacy lockfiles
      dev: info.dev === true,
    });
    if (info.dependencies && typeof info.dependencies === "object") fromDependencies(info.dependencies, out);
  }
}

/** Parse a package-lock.json (lockfile v1/v2/v3) into normalized package records. */
export function parseLockfile(text: string): PackageRecord[] {
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    throw new WormguardError("invalid lockfile JSON");
  }
  if (!json || typeof json !== "object") throw new WormguardError("lockfile is not an object");
  if (json.packages && typeof json.packages === "object") return fromPackages(json.packages);
  if (json.dependencies && typeof json.dependencies === "object") {
    const out = new Map<string, PackageRecord>();
    fromDependencies(json.dependencies, out);
    return [...out.values()];
  }
  return [];
}
