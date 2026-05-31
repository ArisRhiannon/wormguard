// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Baseline v2: snapshot the inventory + the sha256 of every lifecycle script
// body. The diff catches more than the v1 baseline did:
//
//   - Added / removed / version-changed packages           (low advisory)
//   - Integrity changed for an unchanged version            (critical: tampering)
//   - Resolved URL or registry host changed (same version)  (high)
//   - Package gained a lifecycle script                     (high: worm signature)
//   - Lifecycle script BODY changed for an unchanged version (critical: worm
//     signature; the npm worms of 2025-2026 swap the body of postinstall in
//     a new version, but a same-version body change is unambiguously
//     tampering)
//
// V1 baselines are auto-upgraded on read: missing fields default to null/[],
// and a one-time advisory finding is emitted so users know their next
// snapshot will be richer.

import { createHash } from "node:crypto";
import { type PackageRecord, type Finding, WormguardError } from "./types";
import type { InstalledPackage } from "./inventory";
import { sortFindings } from "./ast/orchestrate";

export interface BaselineEntry {
  version: string;
  integrity: string | null;
  resolved: string | null;
  registryHost: string | null;
  hasInstallScript: boolean;
  /** sha256 of the concatenated lifecycle script bodies, in declaration order
   *  (preinstall|install|postinstall|prepare). null when unavailable. */
  scriptsHash?: string | null;
}

export interface Baseline {
  version: 2;
  packages: Record<string, BaselineEntry>;
}

/** Compute the per-package scripts-hash from an InstalledPackage entry. */
export function computeScriptsHash(p: { scripts: Record<string, string | undefined> } | null): string | null {
  if (!p) return null;
  const ord: Array<"preinstall" | "install" | "postinstall" | "prepare"> = [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
  ];
  const parts: string[] = [];
  for (const k of ord) {
    const body = p.scripts[k];
    if (typeof body === "string") parts.push(`${k}:${body}`);
  }
  if (parts.length === 0) return null;
  return createHash("sha256").update(parts.join("\n"), "utf8").digest("hex");
}

/** Build a baseline from a lockfile inventory + an installed-modules snapshot.
 *  The installed snapshot supplies the lifecycle-script bodies. */
export function snapshot(
  inv: PackageRecord[],
  installed: InstalledPackage[] = [],
): Baseline {
  const byName = new Map<string, InstalledPackage>();
  for (const p of installed) {
    if (!byName.has(p.name)) byName.set(p.name, p);
  }
  const packages: Record<string, BaselineEntry> = {};
  for (const r of inv) {
    const inst = byName.get(r.name);
    packages[r.name] = {
      version: r.version,
      integrity: r.integrity,
      resolved: r.resolved,
      registryHost: r.registryHost,
      hasInstallScript: r.hasInstallScript,
      scriptsHash: inst ? computeScriptsHash({ scripts: inst.scripts as Record<string, string | undefined> }) : null,
    };
  }
  return { version: 2, packages };
}

/** Deterministic, key-sorted serialization (round-trip stable). */
export function serializeBaseline(b: Baseline): string {
  const packages: Record<string, BaselineEntry> = {};
  for (const name of Object.keys(b.packages).sort()) packages[name] = b.packages[name] as BaselineEntry;
  return JSON.stringify({ version: b.version, packages }, null, 2);
}

/** Parse a baseline file. v1 baselines are auto-upgraded to v2 (with
 *  scriptsHash defaulted to undefined; the next `snapshot` populates it). */
export function parseBaseline(text: string): Baseline {
  let j: { version?: unknown; packages?: unknown };
  try {
    j = JSON.parse(text);
  } catch {
    throw new WormguardError("invalid baseline JSON");
  }
  if (!j || typeof j.packages !== "object" || j.packages === null) {
    throw new WormguardError("unrecognized baseline format");
  }
  const v = j.version;
  if (v !== 1 && v !== 2) {
    throw new WormguardError(`unrecognized baseline version: ${String(v)}`);
  }
  // v1 -> v2 upgrade: keep all fields, set scriptsHash to null on every entry.
  if (v === 1) {
    const upgraded: Baseline = { version: 2, packages: {} };
    for (const [k, e] of Object.entries(j.packages as Record<string, BaselineEntry>)) {
      upgraded.packages[k] = { ...e, scriptsHash: null };
    }
    return upgraded;
  }
  return j as Baseline;
}

/** Diff a baseline against a fresh inventory (+ installed snapshot for body
 *  hashes). Flags compromise-shaped changes. */
export function diff(
  oldB: Baseline,
  newInv: PackageRecord[],
  newInstalled: InstalledPackage[] = [],
): Finding[] {
  const newB = snapshot(newInv, newInstalled);
  const out: Finding[] = [];
  const oldNames = new Set(Object.keys(oldB.packages));
  const newNames = new Set(Object.keys(newB.packages));

  for (const n of newNames) {
    if (!oldNames.has(n)) {
      out.push({
        ruleId: "WG-DIFF-ADDED",
        severity: "low",
        pkg: n,
        message: "new dependency added since baseline",
      });
    }
  }
  for (const n of oldNames) {
    if (!newNames.has(n)) {
      out.push({
        ruleId: "WG-DIFF-REMOVED",
        severity: "low",
        pkg: n,
        message: "dependency removed since baseline",
      });
    }
  }

  for (const n of newNames) {
    const o = oldB.packages[n];
    const c = newB.packages[n];
    if (!o || !c) continue;

    if (!o.hasInstallScript && c.hasInstallScript) {
      out.push({
        ruleId: "WG-DIFF-NEW-SCRIPT",
        severity: "high",
        pkg: n,
        message: "package gained a lifecycle script since baseline (worm signature)",
      });
    }

    if (o.version !== c.version) {
      out.push({
        ruleId: "WG-DIFF-VERSION",
        severity: "low",
        pkg: n,
        message: `version changed ${o.version} -> ${c.version}`,
      });
      // Different version: integrity/resolved/scripts comparisons aren't
      // meaningful (the package is a different artifact).
      continue;
    }

    if (o.integrity !== c.integrity) {
      out.push({
        ruleId: "WG-DIFF-INTEGRITY",
        severity: "critical",
        pkg: n,
        message: "integrity changed for the SAME version (content tampering)",
      });
    }
    if (o.resolved !== c.resolved || o.registryHost !== c.registryHost) {
      out.push({
        ruleId: "WG-DIFF-REGISTRY",
        severity: "high",
        pkg: n,
        message: "resolved URL / registry changed for the same version",
      });
    }
    // Script body hash drift on an unchanged version: critical worm signature.
    // Only fire when *both* sides have a scripts hash recorded; if either side
    // is null we have no signal.
    if (
      typeof o.scriptsHash === "string" &&
      typeof c.scriptsHash === "string" &&
      o.scriptsHash !== c.scriptsHash
    ) {
      out.push({
        ruleId: "WG-DIFF-SCRIPT-BODY",
        severity: "critical",
        pkg: n,
        message:
          "lifecycle script BODY changed for the SAME version (worm signature: a published artifact's install script bytes were modified)",
      });
    }
  }
  return sortFindings(out);
}
