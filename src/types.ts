export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface PackageRecord {
  name: string;
  version: string;
  resolved: string | null;
  integrity: string | null;
  registryHost: string | null;
  hasInstallScript: boolean;
  dev: boolean;
}

export interface LifecycleScripts {
  preinstall?: string;
  install?: string;
  postinstall?: string;
  prepare?: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  pkg: string;
  message: string;
}

export class WormguardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WormguardError";
  }
}
