// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Top-level scan pipeline. Wires together:
//   - multi-PM lockfile parsing (src/pm)
//   - node_modules walker (src/inventory.ts)
//   - AST orchestrator (src/ast/orchestrate.ts) [AST + IoC + allowlist + taint]
//   - typosquat detection (src/typosquat.ts)
//   - integrity/registry policy (src/policy.ts)
//   - provenance findings (src/provenance/verify.ts) when registry metadata available
//   - granular config filters (src/config.ts)

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { type Finding, type Severity, SEVERITY_ORDER, type PackageRecord } from "./types";
import { inventoryFromLockfiles } from "./pm/index";
import { parseLockfile } from "./lockfile";
import { scanNodeModules } from "./inventory";
import { analyzeInstalledAst, sortFindings } from "./ast/orchestrate";
import { typosquatFindings } from "./typosquat";
import { policyFindings } from "./policy";
import { provenanceContextFromLockEntry, provenanceFindings, verifyRegistrySignature } from "./provenance/verify";
import type { WormguardConfig, ScriptAllowlistEntry } from "./config";
import { scriptSha256 } from "./corpus/allowlist";
import { iocFuzzyFindings } from "./corpus/iocs-fuzzy";
import { preventionLayerCheck } from "./prevention";

export interface ScanResult {
  findings: Finding[];
  counts: Record<Severity, number>;
  /** Lockfiles that were used in this scan, for the report header. */
  lockfilesUsed: Array<{ packageManager: string; path: string }>;
}

/**
 * Apply config filters AFTER all rules have run, so the allowlist semantics
 * are honored consistently. Granular allowlist (per package, per rule, optional
 * script-hash) overrides nothing it doesn't match.
 */
function applyConfig(
  findings: Finding[],
  cfg: WormguardConfig,
  scriptHashes: Map<string, string[]>,
): Finding[] {
  const ignore = new Set(cfg.ignoreRules ?? []);
  const legacyAllow = new Set(cfg.allowInstallScripts ?? []);
  const granular = cfg.scriptAllowlist ?? [];
  return findings.filter((f) => {
    if (ignore.has(f.ruleId)) return false;
    // Legacy whole-package suppression for script-related rules (deprecated but
    // honored).
    if (legacyAllow.has(f.pkg) && f.ruleId.startsWith("WG-AST-")) return false;
    if (legacyAllow.has(f.pkg) && f.ruleId.startsWith("WG-SHELL-")) return false;
    if (legacyAllow.has(f.pkg) && f.ruleId === "WG-INSTALL-SCRIPT") return false;
    // Granular per-package x rule x script-hash matcher.
    const hashes = scriptHashes.get(f.pkg) ?? [];
    for (const entry of granular as ScriptAllowlistEntry[]) {
      if (entry.package !== f.pkg) continue;
      if (!entry.rules.includes(f.ruleId)) continue;
      if (typeof entry.scriptSha256 === "string") {
        if (!hashes.includes(entry.scriptSha256.toLowerCase())) continue;
      }
      return false; // suppressed
    }
    return true;
  });
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const k = `${f.pkg}|${f.ruleId}|${f.location?.file ?? ""}|${f.location?.line ?? ""}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(f);
    }
  }
  return out;
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

/** Read a normalized inventory from `dir` using the multi-PM detector. */
export function inventoryOf(dir: string): PackageRecord[] {
  const r = inventoryFromLockfiles(dir);
  if (r.records.length > 0) return r.records;
  // Fall back to legacy single-file npm parsing if the unified loader
  // produced nothing (e.g. very old lockfiles).
  const legacy = join(dir, "package-lock.json");
  if (existsSync(legacy)) {
    try {
      return parseLockfile(readFileSync(legacy, "utf8"));
    } catch {
      return [];
    }
  }
  return [];
}

/** Collect provenance evidence per package from the raw lockfile JSON,
 *  if it's npm (only npm carries the registry signatures + dist.attestations
 *  in the lockfile; other PMs don't expose them this way). */
function provenanceForNpm(dir: string, inv: PackageRecord[]): Finding[] {
  const out: Finding[] = [];
  const lockPath = join(dir, "package-lock.json");
  if (!existsSync(lockPath)) return out;
  let lock: { packages?: Record<string, { signatures?: unknown; dist?: unknown }> };
  try {
    lock = JSON.parse(readFileSync(lockPath, "utf8"));
  } catch {
    return out;
  }
  if (!lock.packages) return out;
  const byName = new Map<string, { signatures?: unknown; dist?: unknown }>();
  for (const [k, entry] of Object.entries(lock.packages)) {
    if (!entry || typeof entry !== "object") continue;
    const i = k.lastIndexOf("node_modules/");
    const name = i >= 0 ? k.slice(i + "node_modules/".length) : null;
    if (name) byName.set(name, entry);
  }
  for (const r of inv) {
    if (r.packageManager !== "npm") continue;
    const entry = byName.get(r.name);
    if (!entry) continue;
    const ctx = provenanceContextFromLockEntry(r.name, r.version, entry);
    out.push(...provenanceFindings(ctx));
    // If the lockfile entry carried real signatures, cryptographically
    // verify them with the bundled npm registry public keys. A failure
    // here is critical (mismatch between published signature and bundled
    // key, which is exactly the wire-tamper signal).
    const signatures = (entry as { signatures?: unknown }).signatures;
    if (Array.isArray(signatures) && signatures.length > 0 && r.integrity) {
      const verifyResult = verifyRegistrySignature(
        r.name,
        r.version,
        r.integrity,
        signatures as Array<{ keyid?: string; sig?: string }>,
      );
      if (verifyResult) out.push(verifyResult);
    }
  }
  return out;
}

/** Yarn-berry-without-node_modules (PnP / pnp loose) advisory: we cannot run
 *  the AST analyzer because there are no extracted package.json files. */
function yarnPnpAdvisory(dir: string, lockfilesUsed: Array<{ packageManager: string; path: string }>): Finding[] {
  const isBerry = lockfilesUsed.some((l) => l.packageManager === "yarn-berry");
  if (!isBerry) return [];
  const nm = join(dir, "node_modules");
  if (existsSync(nm)) return [];
  return [
    {
      ruleId: "WG-YARN-PNP-NO-NODE-MODULES",
      severity: "medium",
      pkg: "<project>",
      message:
        "yarn-berry lockfile detected but node_modules/ is absent (likely PnP mode). wormguard cannot run AST analysis on lifecycle scripts in this mode. Either set `nodeLinker: node-modules` in .yarnrc.yml, or run with `--mode=update-lockfile` and re-install with a node-modules linker.",
    },
  ];
}

/** Full scan of a project directory. */
export function scan(dir: string, cfg: WormguardConfig = {}): ScanResult {
  const inv = inventoryOf(dir);
  const lockfilesUsed = inventoryFromLockfiles(dir).lockfilesUsed;
  const installed = scanNodeModules(dir);

  // Compute per-package script hashes, used by the granular allowlist.
  const scriptHashes = new Map<string, string[]>();
  for (const p of installed) {
    const arr: string[] = [];
    for (const body of Object.values(p.scripts)) {
      if (typeof body === "string" && body.length > 0) arr.push(scriptSha256(body));
    }
    if (arr.length > 0) scriptHashes.set(p.name, arr);
  }

  const ast = analyzeInstalledAst(installed, {
    ...(cfg.scriptFingerprints ? { scriptFingerprints: cfg.scriptFingerprints } : {}),
  });
  const names = [...new Set([...inv.map((r) => r.name), ...installed.map((p) => p.name)])];
  const raw: Finding[] = [
    ...ast.findings,
    ...typosquatFindings(names),
    ...iocFuzzyFindings(names),
    ...policyFindings(inv, {
      ...(cfg.allowedHosts ? { allowedHosts: cfg.allowedHosts } : {}),
      ...(typeof cfg.allowMissingIntegrity === "boolean"
        ? { allowMissingIntegrity: cfg.allowMissingIntegrity }
        : {}),
    }),
    ...provenanceForNpm(dir, inv),
    ...yarnPnpAdvisory(dir, lockfilesUsed),
    ...(() => {
      const r = preventionLayerCheck(dir, lockfilesUsed.length > 0);
      return r.finding ? [r.finding] : [];
    })(),
  ];
  const findings = sortFindings(dedupe(applyConfig(raw, cfg, scriptHashes)));
  return { findings, counts: countBySeverity(findings), lockfilesUsed };
}

/** True if any finding is at or above the fail severity. */
export function meetsFail(findings: Finding[], failSeverity: Severity): boolean {
  const t = SEVERITY_ORDER[failSeverity];
  return findings.some((f) => SEVERITY_ORDER[f.severity] >= t);
}
