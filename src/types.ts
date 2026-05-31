// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon

export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export type PackageManager = "npm" | "pnpm" | "yarn-classic" | "yarn-berry" | "bun";

export interface PackageRecord {
  /** Package name as it appears in the registry. */
  name: string;
  /** Resolved version string. */
  version: string;
  /** Resolved tarball URL or workspace pointer. May be null for workspace packages. */
  resolved: string | null;
  /** Subresource Integrity string from the lockfile (sha512-... format). */
  integrity: string | null;
  /** Hostname extracted from `resolved`, or null if unresolvable. */
  registryHost: string | null;
  /** True if the lockfile records a lifecycle script for this package. */
  hasInstallScript: boolean;
  /** True if this package is a development-only dependency. */
  dev: boolean;
  /** Which package manager produced the lockfile this came from. */
  packageManager: PackageManager;
  /** npm provenance attestation present in the lockfile (npm v3+). */
  hasProvenance?: boolean | undefined;
}

export interface LifecycleScripts {
  preinstall?: string;
  install?: string;
  postinstall?: string;
  prepare?: string;
}

/** A finding produced by the analyzer pipeline. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  pkg: string;
  message: string;
  /** Optional location info (file path relative to package root, line number). */
  location?: { file?: string; line?: number; column?: number };
  /** Optional evidence snippet (max ~200 chars) used by the human report. */
  evidence?: string;
  /** Optional related rule ids that contributed to this finding (for taint chains). */
  relatedTo?: string[];
}

export class WormguardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WormguardError";
  }
}

/** Categories of dangerous behaviors the AST analyzer reports. Used to drive scoring + taint. */
export type AstCategory =
  | "eval" /* eval, new Function, vm.runIn* */
  | "dynamic-require" /* require(<non-literal>), import(<non-literal>) */
  | "network-builtin" /* require('http' | 'https' | 'net' | 'tls' | 'dns' | 'dgram') */
  | "fetch" /* fetch() */
  | "child-process" /* child_process.exec/spawn/fork */
  | "fs-write-outside" /* fs.writeFile to a path outside cwd / inside node_modules */
  | "env-read" /* process.env / process.env[X] */
  | "secret-path" /* string literal references ~/.npmrc, ~/.aws, .git/config, etc. */
  | "base64-decode" /* Buffer.from(*, 'base64') with literal arg */
  | "crypto-key-read" /* crypto.createPrivateKey, fs.readFile of *.pem etc */
  | "shell-pipe" /* exec("... | sh") in raw string */
  | "string-concat-eval" /* string concatenation feeding eval/Function */
  | "worm-propagate" /* writes to package.json + invokes npm publish (self-propagation primitive) */
  | "import-meta-resolve" /* dynamic import.meta.resolve in install context */;

export interface AstHit {
  category: AstCategory;
  /** raw evidence (already truncated). */
  evidence: string;
  line: number;
  column: number;
  /** if a literal value was constant-folded from concat, capture it. */
  resolvedLiteral?: string;
  /** if base64 decoded, the decoded preview (truncated). */
  decodedPreview?: string;
}

export interface AstReport {
  file: string;
  hits: AstHit[];
  /** True if the analyzer encountered a parse error and fell back to regex on the raw text. */
  parseFallback: boolean;
  /** True if a taint flow from a source (env-read / secret-path / crypto-key-read) reached a sink (network/fetch/child-process). */
  taintToSink: boolean;
  /** Categories observed in source positions for the taint chain. */
  taintSources: AstCategory[];
  /** Categories observed in sink positions for the taint chain. */
  taintSinks: AstCategory[];
}