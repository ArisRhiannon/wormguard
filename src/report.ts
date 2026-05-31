import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { type Finding, type Severity, SEVERITY_ORDER } from "./types";
import { parseLockfile } from "./lockfile";
import { scanNodeModules } from "./inventory";
import { analyzeScripts, sortFindings } from "./analyze";
import { typosquatFindings } from "./typosquat";
import { policyFindings } from "./policy";
import type { WormguardConfig } from "./config";

const SCRIPT_RULE_IDS = new Set([
  "WG-INSTALL-SCRIPT", "WG-SHELL-PIPE", "WG-NET-DOWNLOAD", "WG-CHILD-PROCESS",
  "WG-EVAL", "WG-SECRET-PATH", "WG-ENV-ENUM", "WG-BASE64", "WG-SELF-PROPAGATE",
]);

export interface ScanResult {
  findings: Finding[];
  counts: Record<Severity, number>;
}

function applyConfig(findings: Finding[], cfg: WormguardConfig): Finding[] {
  const ignore = new Set(cfg.ignoreRules ?? []);
  const allowScripts = new Set(cfg.allowInstallScripts ?? []);
  return findings.filter((f) => !ignore.has(f.ruleId) && !(allowScripts.has(f.pkg) && SCRIPT_RULE_IDS.has(f.ruleId)));
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const k = `${f.pkg}|${f.ruleId}`;
    if (!seen.has(k)) { seen.add(k); out.push(f); }
  }
  return out;
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

/** Read the inventory from `<dir>/package-lock.json` (empty if absent). */
export function inventoryOf(dir: string) {
  const lock = join(dir, "package-lock.json");
  return existsSync(lock) ? parseLockfile(readFileSync(lock, "utf8")) : [];
}

/** Full scan of a project directory: scripts + typosquat + policy, config-filtered. */
export function scan(dir: string, cfg: WormguardConfig = {}): ScanResult {
  const inv = inventoryOf(dir);
  const installed = scanNodeModules(dir);
  const names = [...new Set([...inv.map((r) => r.name), ...installed.map((p) => p.name)])];
  const raw = [
    ...analyzeScripts(installed),
    ...typosquatFindings(names),
    ...policyFindings(inv, cfg),
  ];
  const findings = sortFindings(dedupe(applyConfig(raw, cfg)));
  return { findings, counts: countBySeverity(findings) };
}

/** True if any finding is at or above the fail severity. */
export function meetsFail(findings: Finding[], failSeverity: Severity): boolean {
  const t = SEVERITY_ORDER[failSeverity];
  return findings.some((f) => SEVERITY_ORDER[f.severity] >= t);
}
