import { type Finding, SEVERITY_ORDER } from "./types";
import type { InstalledPackage } from "./inventory";
import { SCRIPT_RULES } from "./rules";

/** Deterministic sort: severity desc, then package asc, then rule id asc. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.pkg.localeCompare(b.pkg) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

/** Analyze installed packages' lifecycle scripts for danger signals. */
export function analyzeScripts(installed: InstalledPackage[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (pkg: string, ruleId: string, severity: Finding["severity"], message: string): void => {
    const key = `${pkg}|${ruleId}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId, severity, pkg, message });
  };
  for (const p of installed) {
    const entries = Object.entries(p.scripts);
    if (entries.length === 0) continue;
    push(p.name, "WG-INSTALL-SCRIPT", "low", `defines lifecycle script(s): ${entries.map(([k]) => k).join(", ")}`);
    for (const [, cmd] of entries) {
      for (const rule of SCRIPT_RULES) {
        if (rule.re.test(cmd)) push(p.name, rule.id, rule.severity, rule.message);
      }
    }
  }
  return sortFindings(findings);
}
