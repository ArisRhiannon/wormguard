// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// AST-grade per-package analyzer. Replaces the old regex-only analyzeScripts.
//
// For each installed package this module:
//   1. Computes a sha256 of every lifecycle script body.
//   2. Resolves shell commands -> JS sources (via src/ast/shell.ts).
//   3. Runs acorn-based AST analysis on every resolved source.
//   4. Cross-references with the script-fingerprint allowlist:
//        - "match"  -> drop *all* AST hits for this package's lifecycles
//                      (false-positive suppression, addresses critique #3)
//        - "drift"  -> emit WG-SCRIPT-FINGERPRINT-DRIFT (critical) AND keep
//                      the AST findings (this is the worm-injection signature)
//        - "unknown"-> emit AST findings normally
//   5. Cross-references with the IoC corpus:
//        - matchPackageName  -> WG-IOC-NAME (critical)
//        - matchScriptHash   -> WG-IOC-SCRIPT-HASH (critical)
//        - matchDomains      -> WG-IOC-DOMAIN (critical)
//   6. Applies taint scoring: env-read/secret-path -> network/fetch/child-process
//      escalates the AST findings from medium to high.
//
// All findings are deterministic (sorted) and deduped (unique pkg|ruleId).

import { type Finding, type Severity, SEVERITY_ORDER, type AstReport } from "../types";
import type { InstalledPackage } from "../inventory";
import { analyzeSource } from "./analyzer";
import { resolveShellCommand } from "./shell";
import {
  checkFingerprint,
  fingerprintDriftFinding,
  isAllowlistedPackage,
  scriptSha256,
} from "../corpus/allowlist";
import { matchPackageName, matchDomains, matchScriptHash } from "../corpus/iocs";

/** Map AST hit categories to rule ids + base severities. */
const AST_RULE: Record<string, { id: string; severity: Severity; message: string }> = {
  eval: {
    id: "WG-AST-EVAL",
    severity: "high",
    message: "uses eval / new Function / vm.runIn* (dynamic code execution)",
  },
  "string-concat-eval": {
    id: "WG-AST-CONCAT-EVAL",
    severity: "high",
    message: "feeds a non-literal (concatenated/dynamic) value to eval — obfuscation pattern",
  },
  "dynamic-require": {
    id: "WG-AST-DYNAMIC-REQUIRE",
    severity: "medium",
    message: "require()/import() called with a non-literal argument (cannot be statically resolved)",
  },
  "network-builtin": {
    id: "WG-AST-NETWORK-BUILTIN",
    severity: "high",
    message: "uses a Node network builtin (http/https/net/tls/dns/dgram) during install",
  },
  fetch: {
    id: "WG-AST-FETCH",
    severity: "high",
    message: "uses fetch() during install",
  },
  "child-process": {
    id: "WG-AST-CHILD-PROCESS",
    severity: "medium",
    message: "spawns a child process during install (medium by default; many native packages do this legitimately)",
  },
  "fs-write-outside": {
    id: "WG-AST-FS-WRITE",
    severity: "medium",
    message: "writes to the filesystem during install",
  },
  "env-read": {
    id: "WG-AST-ENV-READ",
    severity: "low",
    message: "reads process.env during install (common for platform detection; only escalates with a network sink)",
  },
  "secret-path": {
    id: "WG-AST-SECRET-PATH",
    severity: "high",
    message: "references a credential / secret file path during install",
  },
  "base64-decode": {
    id: "WG-AST-BASE64",
    severity: "medium",
    message: "decodes a base64 literal during install (possible obfuscated payload)",
  },
  "crypto-key-read": {
    id: "WG-AST-CRYPTO-KEY",
    severity: "high",
    message: "reads/uses cryptographic private-key material during install",
  },
  "shell-pipe": {
    id: "WG-AST-SHELL-PIPE",
    severity: "critical",
    message: "pipes a downloaded payload into a shell (download-and-run)",
  },
  "import-meta-resolve": {
    id: "WG-AST-IMPORT-META",
    severity: "medium",
    message: "uses import.meta.resolve dynamically during install",
  },
};

const SHELL_RULE: Record<string, { id: string; severity: Severity; message: string }> = {
  "shell-pipe-to-shell": {
    id: "WG-SHELL-PIPE",
    severity: "critical",
    message: "lifecycle command pipes content into a shell (curl|sh-style download-and-run)",
  },
  "network-fetch-tool": {
    id: "WG-SHELL-NET-DOWNLOAD",
    severity: "high",
    message: "lifecycle command invokes a network download/transfer tool (curl/wget/nc/...)",
  },
  "shell-base64-decode": {
    id: "WG-SHELL-BASE64",
    severity: "medium",
    message: "lifecycle command decodes base64 in the shell (possible obfuscation)",
  },
  "shell-eval": {
    id: "WG-SHELL-EVAL",
    severity: "high",
    message: "lifecycle command uses shell `eval` or `source`",
  },
  "non-node-binary": {
    id: "WG-SHELL-NON-NODE",
    severity: "low",
    message: "lifecycle command runs a non-node binary (advisory only)",
  },
  "shell-write-secret": {
    id: "WG-SHELL-WRITE-SECRET",
    severity: "high",
    message: "lifecycle command writes into a credential / secret path",
  },
};

export interface AstAnalysisOptions {
  /** Extra fingerprints to merge with the bundled allowlist. */
  scriptFingerprints?: Record<string, string[]>;
}

export interface AstAnalysisResult {
  findings: Finding[];
  /** Per-package raw evidence (AST reports) for the human report and for
   *  baseline snapshots. */
  reports: Array<{ pkg: string; lifecycle: string; report: AstReport }>;
}

function escalateForTaint(severity: Severity, report: AstReport): Severity {
  if (!report.taintToSink) return severity;
  // Promote one rung when taint chain reaches a sink.
  if (severity === "low") return "medium";
  if (severity === "medium") return "high";
  if (severity === "high") return "critical";
  return severity;
}

/** Sort findings deterministically: severity desc, pkg asc, ruleId asc. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.pkg.localeCompare(b.pkg) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

/** Run AST + IoC + allowlist + taint scoring across an installed-package set. */
export function analyzeInstalledAst(
  installed: InstalledPackage[],
  opts: AstAnalysisOptions = {},
): AstAnalysisResult {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const reports: AstAnalysisResult["reports"] = [];
  const push = (f: Finding): void => {
    const k = `${f.pkg}|${f.ruleId}|${f.location?.file ?? ""}|${f.location?.line ?? ""}`;
    if (seen.has(k)) return;
    seen.add(k);
    findings.push(f);
  };

  for (const p of installed) {
    // 1. IoC name match — applies regardless of lifecycle scripts.
    const iocName = matchPackageName(p.name);
    if (iocName) push(iocName);

    const entries = Object.entries(p.scripts) as Array<["preinstall" | "install" | "postinstall" | "prepare", string]>;
    if (entries.length === 0) continue;

    // 2. Fingerprint check across all lifecycle scripts of this package.
    //    A package is allowlisted iff EVERY lifecycle body matches an
    //    accepted hash. Otherwise: "drift" if it's a known package, or
    //    "unknown" if it's not in the allowlist at all.
    let allMatch = true;
    let anyDrift = false;
    let driftLifecycle = "";
    let driftSha = "";
    let inAllowlist = false;
    for (const [lc, body] of entries) {
      const r = checkFingerprint(p.name, body, opts.scriptFingerprints);
      if (r.status !== "match") allMatch = false;
      if (r.status === "drift") {
        anyDrift = true;
        driftLifecycle = lc;
        driftSha = r.sha256;
      }
      if (r.status === "match" || r.status === "drift") inAllowlist = true;
    }
    // Override: if the package name is in the allowlist (any user extras count),
    // we use the same logic.
    if (!inAllowlist) {
      inAllowlist = isAllowlistedPackage(p.name, opts.scriptFingerprints);
    }

    // 3. Bundled IoC: if any lifecycle body's hash is in the malicious-script
    //    corpus, that's an immediate critical hit.
    for (const [lc, body] of entries) {
      const sha = scriptSha256(body);
      const ioc = matchScriptHash(p.name, sha);
      if (ioc) push({ ...ioc, message: `${ioc.message} (${lc})` });
    }

    // 4. Run AST analysis on every resolved JS source.
    for (const [lc, body] of entries) {
      const resolution = resolveShellCommand(p.dir, body);
      // Shell-level findings.
      for (const h of resolution.shellHits) {
        const rule = SHELL_RULE[h.category];
        if (!rule) continue;
        push({
          ruleId: rule.id,
          severity: rule.severity,
          pkg: p.name,
          message: rule.message,
          evidence: h.evidence,
          location: { file: lc },
        });
      }
      // AST findings.
      for (const src of resolution.sources) {
        const report = analyzeSource(src.file, src.source);
        reports.push({ pkg: p.name, lifecycle: lc, report });
        for (const hit of report.hits) {
          const rule = AST_RULE[hit.category];
          if (!rule) continue;
          const escalated = escalateForTaint(rule.severity, report);
          push({
            ruleId: rule.id,
            severity: escalated,
            pkg: p.name,
            message:
              report.taintToSink && escalated !== rule.severity
                ? `${rule.message} (escalated: source-to-sink taint chain detected: ${report.taintSources.join(",")} -> ${report.taintSinks.join(",")})`
                : rule.message,
            evidence: hit.evidence,
            location: { file: src.file, line: hit.line, column: hit.column },
          });
        }
        // IoC domain match within source.
        const domains = matchDomains(src.source);
        for (const d of domains) {
          push({
            ruleId: "WG-IOC-DOMAIN",
            severity: "critical",
            pkg: p.name,
            message: `lifecycle script references known C2/exfil domain "${d}" (offline IoC corpus)`,
            evidence: d,
            location: { file: src.file },
          });
        }
        if (report.parseFallback) {
          push({
            ruleId: "WG-AST-PARSE-FAILED",
            severity: "medium",
            pkg: p.name,
            message:
              "AST parse failed; regex-fallback used. Hard-to-parse install scripts are themselves suspicious.",
            location: { file: src.file },
          });
        }
      }
    }

    // 5. Fingerprint resolution: emit drift OR suppress the package's
    //    AST findings entirely if everything matched a known-good hash.
    if (anyDrift) {
      push(fingerprintDriftFinding(p.name, driftSha, driftLifecycle));
    } else if (allMatch && inAllowlist) {
      // Drop AST/shell findings for allowlisted packages whose every script
      // body is a known-good fingerprint. Keep only the drift/IoC findings
      // (which weren't emitted in this branch).
      const keep = (f: Finding): boolean => {
        if (f.pkg !== p.name) return true;
        return (
          f.ruleId === "WG-IOC-NAME" ||
          f.ruleId === "WG-IOC-SCRIPT-HASH" ||
          f.ruleId === "WG-SCRIPT-FINGERPRINT-DRIFT"
        );
      };
      // Filter in-place.
      const filtered = findings.filter(keep);
      findings.length = 0;
      for (const f of filtered) findings.push(f);
      // Emit a low-severity advisory so the report still shows the package was scanned.
      push({
        ruleId: "WG-INSTALL-SCRIPT-ALLOWLISTED",
        severity: "low",
        pkg: p.name,
        message: `lifecycle scripts match known-good fingerprints for "${p.name}" — findings suppressed`,
      });
    } else {
      // Inventory advisory.
      push({
        ruleId: "WG-INSTALL-SCRIPT",
        severity: "low",
        pkg: p.name,
        message: `defines lifecycle script(s): ${entries.map(([k]) => k).join(", ")}`,
      });
    }
  }

  return { findings: sortFindings(findings), reports };
}
