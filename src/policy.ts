import type { PackageRecord, Finding } from "./types";

export interface PolicyOptions {
  allowedHosts?: string[];
  allowMissingIntegrity?: boolean;
}

const DEFAULT_HOSTS = ["registry.npmjs.org"];

/** Flag insecure transport, non-allowed registries, and missing integrity. */
export function policyFindings(inv: PackageRecord[], opts: PolicyOptions = {}): Finding[] {
  const hosts = new Set(opts.allowedHosts ?? DEFAULT_HOSTS);
  const out: Finding[] = [];
  for (const r of inv) {
    if (r.resolved) {
      if (r.resolved.startsWith("http://")) {
        out.push({ ruleId: "WG-INSECURE-RESOLVED", severity: "high", pkg: r.name, message: "package resolved over insecure http://" });
      }
      if (r.registryHost && !hosts.has(r.registryHost)) {
        out.push({ ruleId: "WG-UNKNOWN-REGISTRY", severity: "medium", pkg: r.name, message: `resolved from non-allowed registry host "${r.registryHost}"` });
      }
      if (!r.integrity && !opts.allowMissingIntegrity) {
        out.push({ ruleId: "WG-NO-INTEGRITY", severity: "medium", pkg: r.name, message: "missing integrity hash" });
      }
    }
  }
  return out;
}
