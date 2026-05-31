// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Public API of `wormguard`. Stable surface only.
//
// The legacy v0 regex-based analyzer (`src/analyze.ts` -> `analyzeScripts`)
// and its rule list (`src/rules.ts` -> `SCRIPT_RULES`) are NOT re-exported
// from here in v1 — they remain in the source tree only as a fallback used
// by tests that exercise the old API. Production code should use `scan()`.

export type {
  Severity,
  PackageManager,
  PackageRecord,
  LifecycleScripts,
  Finding,
  AstCategory,
  AstHit,
  AstReport,
} from "./types";
export { SEVERITY_ORDER, WormguardError } from "./types";

// PM-aware lockfile loaders (preferred over the legacy `parseLockfile`).
export { inventoryFromLockfiles } from "./pm/index";
export { detectLockfiles } from "./pm/detect";
export { parseLockfile } from "./lockfile";

// Inventory walker (multi-layout: npm, pnpm, yarn).
export type { InstalledPackage } from "./inventory";
export { scanNodeModules } from "./inventory";

// AST analyzer + shell resolver.
export { analyzeSource, foldString } from "./ast/analyzer";
export { resolveShellCommand, resolvePackageLifecycle } from "./ast/shell";
export type { ShellResolution, InvokedSource, ShellCategory } from "./ast/shell";

// Orchestrator (the supported entry for in-process use).
export { analyzeInstalledAst, sortFindings } from "./ast/orchestrate";

// Baseline + diff (v2).
export {
  snapshot,
  serializeBaseline,
  parseBaseline,
  diff,
  computeScriptsHash,
} from "./baseline";
export type { Baseline, BaselineEntry } from "./baseline";

// Corpus + provenance.
export {
  matchPackageName,
  matchScriptHash,
  matchDomains,
  matchWallets,
  corpusStats,
  resetCorpusCache,
} from "./corpus/iocs";
export {
  scriptSha256,
  isAllowlistedPackage,
  checkFingerprint,
  fingerprintDriftFinding,
  resetAllowlistCache,
} from "./corpus/allowlist";
export {
  provenanceContextFromLockEntry,
  provenanceFindings,
  verifyBundle,
  verifyRegistrySignature,
  resetProvenanceKeyCache,
  findLocalBundle,
} from "./provenance/verify";

// Heuristics that remain useful at the public level.
export { editDistance } from "./distance";
export { TOP_NAMES } from "./top-names";
export { typosquatFindings } from "./typosquat";
export { policyFindings } from "./policy";

// Config + top-level scan / report.
export type { WormguardConfig, ScriptAllowlistEntry } from "./config";
export { loadConfig } from "./config";
export type { ScanResult } from "./report";
export { scan, meetsFail, inventoryOf, countBySeverity } from "./report";

// ---------------------------------------------------------------------------
// Legacy / deprecated APIs. Kept under explicit names so existing imports
// don't silently break, but NOT re-exported from the package root above.
// Use `scan()` instead.
// ---------------------------------------------------------------------------

import { analyzeScripts as _legacyAnalyzeScripts } from "./analyze";
import { SCRIPT_RULES as _legacySCRIPT_RULES } from "./rules";

/**
 * @deprecated Use `scan()` (or `analyzeInstalledAst()`) instead. This is the
 * v0 regex-based analyzer, retained only for backward compatibility.
 */
export const analyzeScripts = _legacyAnalyzeScripts;

/**
 * @deprecated Use the AST analyzer's category map. Retained only for
 * backward compatibility.
 */
export const SCRIPT_RULES = _legacySCRIPT_RULES;
