#!/usr/bin/env bun
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// wormguard CLI. Subcommands:
//
//   scan      [dir] [--json] [--ci]                        AST + IoC + provenance + policy + typosquat
//   snapshot  [dir] [--out <file>]                         write a baseline (inventory + script body hashes)
//   audit     [dir] [--baseline <file>] [--json] [--ci]    diff against the baseline AND re-run scan; both sets fail the gate
//   refresh                                                 update the bundled IoC corpus from GHSA (only network call)
//   help

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { type Finding, type Severity } from "./types";
import { scan, meetsFail, inventoryOf, countBySeverity } from "./report";
import { loadConfig } from "./config";
import { snapshot, serializeBaseline, parseBaseline, diff } from "./baseline";
import { scanNodeModules } from "./inventory";
import { corpusStats } from "./corpus/iocs";

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

const HELP = `wormguard — offline AST-grade supply-chain auditor for npm/pnpm/yarn/bun
usage:
  wormguard scan [dir] [--json] [--ci]
      AST + IoC corpus + provenance + policy + typosquat audit. Read-only.
  wormguard snapshot [dir] [--out <file>]
      Snapshot inventory + script body hashes; default: <dir>/.wormguard-baseline.json
  wormguard audit [dir] [--baseline <file>] [--json] [--ci]
      Diff against the baseline AND re-run scan; both sets gate the exit.
  wormguard refresh
      Refresh the bundled IoC corpus from the GHSA type=malware feed
      (the only network-touching subcommand; honors GITHUB_TOKEN).
  wormguard help
flags:
  --json      machine-readable output
  --ci        exit non-zero if any finding >= fail severity (default: high)
  --baseline  path to a baseline file (audit only)
  --out       path to write a baseline (snapshot only)
config: .wormguard.json (see README)`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const rest = argv.slice(1);
let json = false;
let ci = false;
let baseline: string | undefined;
let out: string | undefined;
const pos: string[] = [];
for (let i = 0; i < rest.length; i++) {
  const a = rest[i] as string;
  if (a === "--") {
    for (let j = i + 1; j < rest.length; j++) {
      const t = rest[j];
      if (t !== undefined) pos.push(t);
    }
    break;
  }
  if (a === "--json") json = true;
  else if (a === "--ci") ci = true;
  else if (a === "--baseline") {
    const v = rest[++i];
    if (v) baseline = v;
  } else if (a === "--out") {
    const v = rest[++i];
    if (v) out = v;
  } else if (!a.startsWith("--")) {
    pos.push(a);
  }
}
const dir = pos[0] ?? ".";

function fmt(findings: Finding[]): string {
  if (findings.length === 0) return "wormguard: no findings.";
  return findings
    .map((f) => {
      const loc = f.location?.file ? `  ${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "";
      return `${f.severity.toUpperCase().padEnd(8)} ${f.ruleId.padEnd(28)} ${f.pkg}  — ${f.message}${loc}`;
    })
    .join("\n");
}

function emit(findings: Finding[], failSeverity: Severity, header?: string): never {
  const counts = countBySeverity(findings);
  if (json) {
    console.log(JSON.stringify({ findings, counts, header: header ?? null }, null, 2));
  } else {
    if (header) console.log(header);
    console.log(fmt(findings));
    console.log(
      `\ncritical=${counts.critical} high=${counts.high} medium=${counts.medium} low=${counts.low}`,
    );
  }
  process.exit(ci && meetsFail(findings, failSeverity) ? 1 : 0);
}

function fmtHeader(dirArg: string, lockfilesUsed: Array<{ packageManager: string; path: string }>, extra?: string): string {
  const stats = corpusStats();
  const lf = lockfilesUsed.length === 0
    ? "no lockfile detected"
    : lockfilesUsed.map((l) => `${l.packageManager}: ${l.path}`).join(", ");
  const corpus = stats.size > 0 ? `IoC corpus: ${stats.size} names (fetched ${stats.fetchedAt || "unknown"})` : "IoC corpus: empty (run `wormguard refresh`)";
  const tail = extra ? `\n${extra}` : "";
  return `# wormguard audit @ ${dirArg}\n# ${lf}\n# ${corpus}${tail}`;
}

function thisDir(): string {
  return dirname(fileURLToPath(import.meta.url));
}

switch (cmd) {
  case "scan": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const cfg = loadConfig(dir);
    const result = scan(dir, cfg);
    emit(result.findings, cfg.failSeverity ?? "high", fmtHeader(dir, result.lockfilesUsed));
    break;
  }
  case "snapshot": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const file = out ?? join(dir, ".wormguard-baseline.json");
    const inv = inventoryOf(dir);
    const installed = scanNodeModules(dir);
    const base = snapshot(inv, installed);
    writeFileSync(file, serializeBaseline(base));
    console.log(
      `wormguard: baseline v2 written to ${file} (${Object.keys(base.packages).length} packages, ${
        Object.values(base.packages).filter((p) => typeof p.scriptsHash === "string").length
      } with script body hashes)`,
    );
    break;
  }
  case "audit": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const file = baseline ?? join(dir, ".wormguard-baseline.json");
    if (!existsSync(file)) die(`no baseline at ${file}; run: wormguard snapshot ${dir}`);
    const cfg = loadConfig(dir);
    const ignore = new Set(cfg.ignoreRules ?? []);
    const old = parseBaseline(readFileSync(file, "utf8"));
    const inv = inventoryOf(dir);
    const installed = scanNodeModules(dir);
    const diffFindings = diff(old, inv, installed).filter((f) => !ignore.has(f.ruleId));
    // Also re-run the live scan so worm-injection signatures (script
    // fingerprint drift, IoC matches, AST hits on a current install) gate
    // the audit too — not just delta-from-baseline changes.
    const liveResult = scan(dir, cfg);
    const seen = new Set<string>();
    const merged: Finding[] = [];
    for (const f of [...diffFindings, ...liveResult.findings]) {
      const k = `${f.pkg}|${f.ruleId}|${f.location?.file ?? ""}|${f.location?.line ?? ""}`;
      if (!seen.has(k)) {
        seen.add(k);
        merged.push(f);
      }
    }
    emit(
      merged,
      cfg.failSeverity ?? "high",
      fmtHeader(dir, liveResult.lockfilesUsed, `# baseline: ${file} (v${old.version})`),
    );
    break;
  }
  case "refresh": {
    // Resolve the populator script alongside the bundled cli (sibling tree).
    const here = thisDir();
    const populator = resolve(here, "..", "scripts", "refresh-corpus.ts");
    if (!existsSync(populator)) {
      die(`refresh script not found at ${populator}; install wormguard from source to refresh the corpus.`);
    }
    const result = spawnSync("bun", ["run", populator], { stdio: "inherit", env: process.env });
    process.exit(result.status ?? 1);
  }
  case "help":
  case "--help":
  case "-h":
  case undefined:
    console.log(HELP);
    break;
  default:
    die(`unknown command: ${cmd}\n\n${HELP}`, 2);
}
