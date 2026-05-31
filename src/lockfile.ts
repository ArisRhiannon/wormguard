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
      packageManager: "npm",
    };
    out.set(`${name}@${version}`, rec);
  }
  return [...out.values()];
}

function fromDependencies(deps: Record<string, any>, out: Map<string, PackageRecord>): void {
  // Iterative breadth-first walk with a hard depth bound. The recursive
  // version was vulnerable to RangeError stack overflow on hostile lockfiles
  // with deeply nested `dependencies` trees (red-team finding C3). The
  // depth bound also doubles as a sanity check: legitimate npm v1 lockfiles
  // do not exceed ~50-100 levels even on the largest monorepos.
  const MAX_DEPTH = 256;
  interface Frame { node: Record<string, any>; depth: number }
  const stack: Frame[] = [{ node: deps, depth: 0 }];
  while (stack.length > 0) {
    const frame = stack.pop() as Frame;
    if (frame.depth > MAX_DEPTH) {
      throw new WormguardError(
        `lockfile dependencies tree exceeds ${MAX_DEPTH} levels of nesting; refusing to walk further (possible DoS or pathologically nested lockfile)`,
      );
    }
    for (const [name, info] of Object.entries(frame.node)) {
      if (!info || typeof info !== "object") continue;
      const version: string = typeof info.version === "string" ? info.version : "";
      const resolved: string | null = typeof info.resolved === "string" ? info.resolved : null;
      out.set(`${name}@${version}`, {
        name,
        version,
        resolved,
        integrity: typeof info.integrity === "string" ? info.integrity : null,
        registryHost: hostOf(resolved),
        hasInstallScript: false,
        dev: info.dev === true,
        packageManager: "npm",
      });
      if (info.dependencies && typeof info.dependencies === "object") {
        stack.push({ node: info.dependencies, depth: frame.depth + 1 });
      }
    }
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
