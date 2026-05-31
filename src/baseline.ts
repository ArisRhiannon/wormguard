import { type PackageRecord, type Finding, WormguardError } from "./types";
import { sortFindings } from "./analyze";

export interface BaselineEntry {
  version: string;
  integrity: string | null;
  resolved: string | null;
  registryHost: string | null;
  hasInstallScript: boolean;
}
export interface Baseline {
  version: 1;
  packages: Record<string, BaselineEntry>;
}

/** Build a baseline from an inventory (keyed by package name). */
export function snapshot(inv: PackageRecord[]): Baseline {
  const packages: Record<string, BaselineEntry> = {};
  for (const r of inv) {
    packages[r.name] = {
      version: r.version,
      integrity: r.integrity,
      resolved: r.resolved,
      registryHost: r.registryHost,
      hasInstallScript: r.hasInstallScript,
    };
  }
  return { version: 1, packages };
}

/** Deterministic, key-sorted serialization (round-trip stable). */
export function serializeBaseline(b: Baseline): string {
  const packages: Record<string, BaselineEntry> = {};
  for (const name of Object.keys(b.packages).sort()) packages[name] = b.packages[name] as BaselineEntry;
  return JSON.stringify({ version: b.version, packages }, null, 2);
}

export function parseBaseline(text: string): Baseline {
  let j: { version?: unknown; packages?: unknown };
  try {
    j = JSON.parse(text);
  } catch {
    throw new WormguardError("invalid baseline JSON");
  }
  if (!j || j.version !== 1 || typeof j.packages !== "object" || j.packages === null) {
    throw new WormguardError("unrecognized baseline format");
  }
  return j as Baseline;
}

/** Diff a baseline against a fresh inventory; flags compromise-shaped changes. */
export function diff(oldB: Baseline, newInv: PackageRecord[]): Finding[] {
  const newB = snapshot(newInv);
  const out: Finding[] = [];
  const oldNames = new Set(Object.keys(oldB.packages));
  const newNames = new Set(Object.keys(newB.packages));

  for (const n of newNames) if (!oldNames.has(n)) out.push({ ruleId: "WG-DIFF-ADDED", severity: "low", pkg: n, message: "new dependency added since baseline" });
  for (const n of oldNames) if (!newNames.has(n)) out.push({ ruleId: "WG-DIFF-REMOVED", severity: "low", pkg: n, message: "dependency removed since baseline" });

  for (const n of newNames) {
    const o = oldB.packages[n];
    const c = newB.packages[n];
    if (!o || !c) continue;
    if (!o.hasInstallScript && c.hasInstallScript) {
      out.push({ ruleId: "WG-DIFF-NEW-SCRIPT", severity: "high", pkg: n, message: "package gained an install script since baseline (worm signature)" });
    }
    if (o.version !== c.version) {
      out.push({ ruleId: "WG-DIFF-VERSION", severity: "low", pkg: n, message: `version changed ${o.version} -> ${c.version}` });
      continue;
    }
    if (o.integrity !== c.integrity) {
      out.push({ ruleId: "WG-DIFF-INTEGRITY", severity: "critical", pkg: n, message: "integrity changed for the SAME version (content tampering)" });
    }
    if (o.resolved !== c.resolved || o.registryHost !== c.registryHost) {
      out.push({ ruleId: "WG-DIFF-REGISTRY", severity: "high", pkg: n, message: "resolved URL / registry changed for the same version" });
    }
  }
  return sortFindings(out);
}
