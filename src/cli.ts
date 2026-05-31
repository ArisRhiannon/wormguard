#!/usr/bin/env bun
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type Finding, type Severity } from "./types";
import { scan, meetsFail, inventoryOf, countBySeverity } from "./report";
import { loadConfig } from "./config";
import { snapshot, serializeBaseline, parseBaseline, diff } from "./baseline";

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

const HELP = `wormguard — offline npm supply-chain auditor (no network, no CVE DB)
usage:
  wormguard scan [dir] [--json] [--ci]        analyze lockfile + node_modules
  wormguard snapshot [dir] [--out <file>]     write a baseline of the current tree
  wormguard audit [dir] [--baseline <file>] [--json] [--ci]
                                              diff the tree against the baseline
flags:
  --json   machine-readable output
  --ci     exit non-zero if any finding is >= fail severity (default: high)`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const rest = argv.slice(1);
let json = false, ci = false, baseline: string | undefined, out: string | undefined;
const pos: string[] = [];
for (let i = 0; i < rest.length; i++) {
  const a = rest[i] as string;
  if (a === "--") { for (let j = i + 1; j < rest.length; j++) { const t = rest[j]; if (t !== undefined) pos.push(t); } break; }
  if (a === "--json") json = true;
  else if (a === "--ci") ci = true;
  else if (a === "--baseline") { const v = rest[++i]; if (v) baseline = v; }
  else if (a === "--out") { const v = rest[++i]; if (v) out = v; }
  else if (!a.startsWith("--")) pos.push(a);
}
const dir = pos[0] ?? ".";

function fmt(findings: Finding[]): string {
  if (findings.length === 0) return "wormguard: no findings.";
  return findings.map((f) => `${f.severity.toUpperCase().padEnd(8)} ${f.ruleId.padEnd(20)} ${f.pkg}  — ${f.message}`).join("\n");
}
function emit(findings: Finding[], failSeverity: Severity): never {
  const counts = countBySeverity(findings);
  if (json) console.log(JSON.stringify({ findings, counts }, null, 2));
  else { console.log(fmt(findings)); console.log(`\ncritical=${counts.critical} high=${counts.high} medium=${counts.medium} low=${counts.low}`); }
  process.exit(ci && meetsFail(findings, failSeverity) ? 1 : 0);
}

switch (cmd) {
  case "scan": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const cfg = loadConfig(dir);
    emit(scan(dir, cfg).findings, cfg.failSeverity ?? "high");
    break;
  }
  case "snapshot": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const file = out ?? join(dir, ".wormguard-baseline.json");
    const base = snapshot(inventoryOf(dir));
    writeFileSync(file, serializeBaseline(base));
    console.log(`wormguard: baseline written to ${file} (${Object.keys(base.packages).length} packages)`);
    break;
  }
  case "audit": {
    if (!existsSync(dir)) die(`no such directory: ${dir}`);
    const file = baseline ?? join(dir, ".wormguard-baseline.json");
    if (!existsSync(file)) die(`no baseline at ${file}; run: wormguard snapshot ${dir}`);
    const cfg = loadConfig(dir);
    const ignore = new Set(cfg.ignoreRules ?? []);
    const old = parseBaseline(readFileSync(file, "utf8"));
    const findings = diff(old, inventoryOf(dir)).filter((f) => !ignore.has(f.ruleId));
    emit(findings, cfg.failSeverity ?? "high");
    break;
  }
  case "help": case "--help": case "-h": case undefined:
    console.log(HELP);
    break;
  default:
    die(`unknown command: ${cmd}\n\n${HELP}`, 2);
}
