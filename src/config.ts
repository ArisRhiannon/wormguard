// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Configuration. The granular allowlist replaces the old whole-package
// `allowInstallScripts` switch from v0 (critique #3, "granularity cero").
//
// New schema:
//
//   {
//     "allowedHosts": ["registry.npmjs.org", "npm.mycorp.example"],
//     "allowMissingIntegrity": false,
//     "ignoreRules": ["WG-INVENTORY-ADDED"],
//     "failSeverity": "high",
//
//     // Granular per-package + per-rule allowlist with optional script hash binding:
//     "scriptAllowlist": [
//       { "package": "esbuild", "rules": ["WG-AST-CHILD-PROCESS"], "scriptSha256": "abc..." },
//       { "package": "my-internal", "rules": ["WG-AST-FETCH"] }
//     ],
//
//     // Extra script fingerprints (sha256 hex) trusted in addition to the bundle:
//     "scriptFingerprints": {
//       "my-tool": ["e3b0c44298..."]
//     }
//   }
//
// The legacy `allowInstallScripts: string[]` is still parsed for backward
// compatibility but emits a deprecation note via the CLI.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Severity } from "./types";

export interface ScriptAllowlistEntry {
  package: string;
  rules: string[];
  /** If set, the allow only applies when the script body sha256 matches. */
  scriptSha256?: string;
}

export interface WormguardConfig {
  allowedHosts?: string[];
  allowMissingIntegrity?: boolean;
  /** Legacy v0 switch — applies to all script-related rules for the whole package. */
  allowInstallScripts?: string[];
  ignoreRules?: string[];
  failSeverity?: Severity;
  /** Granular package x rule x script-hash allowlist. */
  scriptAllowlist?: ScriptAllowlistEntry[];
  /** User-supplied fingerprints to extend the bundled allowlist. */
  scriptFingerprints?: Record<string, string[]>;
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
