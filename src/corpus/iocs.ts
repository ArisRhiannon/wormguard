// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Indicator-of-Compromise matcher.
//
// Loads `data/iocs.json` (built by scripts/refresh-corpus.ts from the public
// GitHub Advisory Database `type=malware` feed) and exposes:
//
//   matchPackageName(name)  -> Finding | null   (exact name match against the
//                                                23k+ confirmed malicious npm
//                                                packages from GHSA)
//   matchScriptHash(sha256) -> Finding | null   (sha256 of a known-malicious
//                                                lifecycle script body)
//   matchDomains(text)      -> string[]         (C2/exfil hostnames found
//                                                anywhere in the script text)
//   matchWallets(text)      -> string[]         (crypto wallet addresses found
//                                                in the script text)
//
// The corpus is bundled, so the matcher works fully offline. The corpus is
// updated by `bun run refresh-corpus` (the only network-touching code path
// in the project).

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Finding } from "../types";

interface IocCorpus {
  version: number;
  fetchedAt: string;
  sources: { ghsa: { count: number; lastIso: string } };
  names: string[];
  scriptSha256: string[];
  domains: string[];
  wallets: string[];
}

const HERE = dirname(fileURLToPath(import.meta.url));
// data/iocs.json sits two levels up from src/corpus/iocs.ts
const CORPUS_PATH = join(HERE, "..", "..", "data", "iocs.json");

interface PreparedCorpus {
  names: Set<string>;
  scriptSha256: Set<string>;
  domains: string[]; // kept ordered by length desc for substring matching
  wallets: Set<string>;
  fetchedAt: string;
  size: number;
}

let cached: PreparedCorpus | null = null;

function emptyCorpus(): PreparedCorpus {
  return {
    names: new Set(),
    scriptSha256: new Set(),
    domains: [],
    wallets: new Set(),
    fetchedAt: "",
    size: 0,
  };
}

function loadCorpus(): PreparedCorpus {
  if (cached) return cached;
  if (!existsSync(CORPUS_PATH)) {
    cached = emptyCorpus();
    return cached;
  }
  let json: IocCorpus;
  try {
    json = JSON.parse(readFileSync(CORPUS_PATH, "utf8")) as IocCorpus;
  } catch {
    cached = emptyCorpus();
    return cached;
  }
  cached = {
    names: new Set(Array.isArray(json.names) ? json.names.map((n) => n.toLowerCase()) : []),
    scriptSha256: new Set(
      Array.isArray(json.scriptSha256) ? json.scriptSha256.map((h) => h.toLowerCase()) : [],
    ),
    domains: Array.isArray(json.domains)
      ? [...json.domains].sort((a, b) => b.length - a.length)
      : [],
    wallets: new Set(Array.isArray(json.wallets) ? json.wallets : []),
    fetchedAt: typeof json.fetchedAt === "string" ? json.fetchedAt : "",
    size: Array.isArray(json.names) ? json.names.length : 0,
  };
  return cached;
}

/** Reset cache (for tests). */
export function resetCorpusCache(): void {
  cached = null;
}

/** Return summary metadata about the loaded corpus. */
export function corpusStats(): { fetchedAt: string; size: number } {
  const c = loadCorpus();
  return { fetchedAt: c.fetchedAt, size: c.size };
}

/** Match an npm package name against the IoC corpus (case-insensitive exact match). */
export function matchPackageName(name: string): Finding | null {
  const c = loadCorpus();
  if (c.names.has(name.toLowerCase())) {
    return {
      ruleId: "WG-IOC-NAME",
      severity: "critical",
      pkg: name,
      message:
        "package name appears in the GitHub Advisory Database malware list (confirmed malicious npm package)",
    };
  }
  return null;
}

/** Match a sha256 (lowercase hex) of a script body against the IoC corpus. */
export function matchScriptHash(name: string, sha256: string): Finding | null {
  const c = loadCorpus();
  if (c.scriptSha256.has(sha256.toLowerCase())) {
    return {
      ruleId: "WG-IOC-SCRIPT-HASH",
      severity: "critical",
      pkg: name,
      message: `lifecycle script body hash (${sha256.slice(0, 16)}…) matches a known-malicious script in the IoC corpus`,
    };
  }
  return null;
}

/** Find any IoC domains present in a free-form text blob (script source, etc). */
export function matchDomains(text: string): string[] {
  const c = loadCorpus();
  const out: string[] = [];
  const lower = text.toLowerCase();
  for (const d of c.domains) {
    if (lower.includes(d)) out.push(d);
  }
  return out;
}

/** Find any IoC wallet addresses in a free-form text blob. */
export function matchWallets(text: string): string[] {
  const c = loadCorpus();
  const out: string[] = [];
  for (const w of c.wallets) {
    if (text.includes(w)) out.push(w);
  }
  return out;
}
