// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Configuration loading.
//
// THREAT MODEL (read this before changing the loader):
//
// wormguard's whole purpose is to detect malicious code introduced into a
// project. The threat model therefore assumes that an attacker may already
// have write access to the project tree (a compromised dependency, a
// commandeered branch, etc.). Reading config from inside the same project
// tree is therefore a CONFUSED-DEPUTY problem: the attacker who lands the
// payload also lands the policy that audits it.
//
// Concretely, a `.wormguard.json` containing
//     { "failSeverity": "low" }
// or  { "ignoreRules": ["WG-SHELL-PIPE", "WG-AST-NETWORK-BUILTIN", ...] }
// or  { "scriptFingerprints": { "<pkg>": ["<sha-of-the-attacker's-script>"] } }
// completely defeats wormguard.
//
// Default behavior (v1.1+):
//
//   1. We do NOT load `.wormguard.json` from the scanned tree by default.
//   2. We load config from, in priority order:
//        a) `--config FILE` CLI flag (path resolved at scan time)
//        b) `WORMGUARD_CONFIG` environment variable (absolute path)
//      Both of these are controlled by the CI runner / operator, not the
//      repo. A compromised repo cannot influence them.
//   3. If a `.wormguard.json` is present in the scanned tree but neither
//      (a) nor (b) is supplied, we EMIT A WARNING (a finding,
//      WG-CONFIG-IN-REPO-IGNORED, low severity) so operators know the
//      file exists and is being ignored.
//   4. If the operator wants the v0 behavior (e.g. for local development
//      where the developer trusts their own repo), they pass
//      `--trust-repo-config`. This explicitly opts in to reading
//      `.wormguard.json` from the scanned tree.

import { readFileSync, existsSync } from "node:fs";
import { isAbsolute, resolve, join } from "node:path";
import { type Severity, type Finding } from "./types";

export interface ScriptAllowlistEntry {
  package: string;
  rules: string[];
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

export interface ConfigLoadOptions {
  /** Absolute (or scan-dir-relative) path to a config file passed via --config. */
  configPath?: string | undefined;
  /** True if the operator passed --trust-repo-config (opts back into reading
   *  .wormguard.json from the scanned tree). */
  trustRepoConfig?: boolean | undefined;
  /** Used in tests to bypass env reading. */
  ignoreEnv?: boolean;
}

export interface ConfigLoadResult {
  config: WormguardConfig;
  /** Where the config came from, for the report header. */
  source: "cli-flag" | "environment" | "in-repo-trusted" | "in-repo-ignored" | "default";
  /** Findings emitted by the loader itself (e.g. WG-CONFIG-IN-REPO-IGNORED). */
  findings: Finding[];
}

function readJsonSafe(path: string): WormguardConfig | null {
  try {
    const j = JSON.parse(readFileSync(path, "utf8"));
    if (j && typeof j === "object" && !Array.isArray(j)) return j as WormguardConfig;
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * Load config according to the trust model documented at the top of this file.
 * `dir` is the scanned project root (where in-repo .wormguard.json would live).
 */
export function loadConfig(dir: string, opts: ConfigLoadOptions = {}): ConfigLoadResult {
  // 1. CLI-supplied path.
  if (typeof opts.configPath === "string" && opts.configPath.length > 0) {
    const abs = isAbsolute(opts.configPath) ? opts.configPath : resolve(dir, opts.configPath);
    const c = existsSync(abs) ? readJsonSafe(abs) : null;
    if (c === null) {
      return {
        config: {},
        source: "default",
        findings: [
          {
            ruleId: "WG-CONFIG-MISSING",
            severity: "medium",
            pkg: "<config>",
            message: `--config ${opts.configPath} did not load (file missing or not a JSON object)`,
          },
        ],
      };
    }
    return { config: c, source: "cli-flag", findings: [] };
  }

  // 2. Environment variable.
  const envPath = opts.ignoreEnv ? "" : (process.env.WORMGUARD_CONFIG ?? "");
  if (envPath) {
    const abs = isAbsolute(envPath) ? envPath : resolve(dir, envPath);
    const c = existsSync(abs) ? readJsonSafe(abs) : null;
    if (c === null) {
      return {
        config: {},
        source: "default",
        findings: [
          {
            ruleId: "WG-CONFIG-MISSING",
            severity: "medium",
            pkg: "<config>",
            message: `WORMGUARD_CONFIG=${envPath} did not load (file missing or not a JSON object)`,
          },
        ],
      };
    }
    return { config: c, source: "environment", findings: [] };
  }

  // 3. In-repo .wormguard.json — opt-in via --trust-repo-config; otherwise IGNORED.
  const inRepo = join(dir, ".wormguard.json");
  if (existsSync(inRepo)) {
    if (opts.trustRepoConfig) {
      const c = readJsonSafe(inRepo);
      if (c !== null) return { config: c, source: "in-repo-trusted", findings: [] };
      return { config: {}, source: "default", findings: [] };
    }
    return {
      config: {},
      source: "in-repo-ignored",
      findings: [
        {
          ruleId: "WG-CONFIG-IN-REPO-IGNORED",
          severity: "low",
          pkg: "<config>",
          message:
            "found .wormguard.json in the scanned tree; ignoring by default (an attacker who controls the repo could craft a permissive config). Pass --config FILE (CI-controlled), set WORMGUARD_CONFIG, or pass --trust-repo-config to opt in.",
        },
      ],
    };
  }

  return { config: {}, source: "default", findings: [] };
}
