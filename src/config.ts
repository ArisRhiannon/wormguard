import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Severity } from "./types";

export interface WormguardConfig {
  allowedHosts?: string[];
  allowMissingIntegrity?: boolean;
  allowInstallScripts?: string[];
  ignoreRules?: string[];
  failSeverity?: Severity;
}

/** Load `.wormguard.json` from `dir`, or return defaults if absent/invalid. */
export function loadConfig(dir: string): WormguardConfig {
  const p = join(dir, ".wormguard.json");
  if (!existsSync(p)) return {};
  try {
    const j = JSON.parse(readFileSync(p, "utf8"));
    return j && typeof j === "object" ? (j as WormguardConfig) : {};
  } catch {
    return {};
  }
}
