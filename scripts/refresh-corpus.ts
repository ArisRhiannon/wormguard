#!/usr/bin/env bun
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Refresh the IoC corpus from the public GitHub Advisory Database.
//
// Source: GHSA REST endpoint
//   https://api.github.com/advisories?ecosystem=npm&type=malware
// using `Link: rel="next"` cursor pagination.
//
// Output schema (data/iocs.json):
//   {
//     "version": 2,
//     "fetchedAt": "2026-...",
//     "sources": { "ghsa": { "advisories": N, "lastIso": "..." } },
//     "names": [ "lower-case-pkg-name", ... ],   // *every* name ever in the feed (legacy lookup)
//     "ranges": {
//       "lower-case-pkg-name": [ "<= 1.2.3", ">=2.0.0 <2.0.5", ... ]   // SemVer ranges
//     },
//     "scriptSha256": [ ... ],
//     "domains": [ ... ],
//     "wallets": [ ... ]
//   }
//
// CRITICAL FIX (red-team C2): we now extract `vulnerable_version_range`
// per advisory so the runtime matcher can verify the *installed* version
// is actually inside an affected range before flagging WG-IOC-NAME. The
// previous v1 schema kept only names, which produced critical FPs on
// legitimately-recovered packages (ansi-regex, chalk, ...).

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const TARGET = "data/iocs.json";

interface GhsaPackage {
  ecosystem: string;
  name: string;
}
interface GhsaVuln {
  package?: GhsaPackage;
  vulnerable_version_range?: string;
}
interface GhsaAdvisory {
  ghsa_id?: string;
  type?: string;
  vulnerabilities?: GhsaVuln[];
  withdrawn_at?: string | null;
  published_at?: string | null;
  updated_at?: string | null;
}

interface FetchResult {
  ranges: Map<string, Set<string>>; // pkgname -> set of range strings
  advisoryCount: number;
  lastIso: string;
}

async function fetchAllGhsaMalware(token?: string): Promise<FetchResult> {
  const ranges = new Map<string, Set<string>>();
  let advisoryCount = 0;
  let lastIso = "";
  let url: string | null =
    "https://api.github.com/advisories?ecosystem=npm&type=malware&per_page=100&sort=published&direction=desc";
  let pages = 0;
  while (url && pages < 250) {
    pages++;
    const headers: Record<string, string> = {
      "user-agent": "wormguard-corpus-refresh",
      accept: "application/vnd.github+json",
    };
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      throw new Error(`GHSA fetch page ${pages} failed: ${res.status} ${res.statusText}`);
    }
    const advisories = (await res.json()) as GhsaAdvisory[];
    if (!Array.isArray(advisories) || advisories.length === 0) break;
    for (const a of advisories) {
      if (a.withdrawn_at) continue;
      advisoryCount++;
      const vulns = a.vulnerabilities ?? [];
      for (const v of vulns) {
        if (v.package?.ecosystem !== "npm" || typeof v.package?.name !== "string") continue;
        const name = v.package.name.toLowerCase();
        const range = typeof v.vulnerable_version_range === "string" ? v.vulnerable_version_range.trim() : "";
        const set = ranges.get(name) ?? new Set<string>();
        // ">= 0" is GHSA's catch-all; we keep it as that's what they advise
        // but the runtime matcher treats it as "all versions affected" only
        // when no narrower range exists for the same name.
        if (range) set.add(range);
        ranges.set(name, set);
      }
      if (a.published_at && a.published_at > lastIso) lastIso = a.published_at;
    }
    const link = res.headers.get("link") ?? "";
    const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
    url = nextMatch ? nextMatch[1] ?? null : null;
    if (url) await new Promise((r) => setTimeout(r, 250));
  }
  console.log(`[corpus] traversed ${pages} GHSA pages, ${advisoryCount} active advisories`);
  return { ranges, advisoryCount, lastIso };
}

interface IocCorpus {
  version: 2;
  fetchedAt: string;
  sources: { ghsa: { advisories: number; lastIso: string } };
  names: string[];
  ranges: Record<string, string[]>;
  scriptSha256: string[];
  domains: string[];
  wallets: string[];
}

const SEED_DOMAINS = [
  "webhook.site",
  "discord.com/api/webhooks",
  "discordapp.com/api/webhooks",
  "telegram.org/bot",
  "api.telegram.org/bot",
  "ngrok-free.app",
  "trycloudflare.com",
];
const SEED_SCRIPT_HASHES: string[] = [];
const SEED_WALLETS: string[] = [];

async function main(): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) console.warn("[corpus] GITHUB_TOKEN unset; using anonymous rate limit (60/h).");

  let existing: Partial<IocCorpus> = {};
  if (existsSync(TARGET)) {
    try {
      existing = JSON.parse(readFileSync(TARGET, "utf8")) as Partial<IocCorpus>;
    } catch {
      /* fall through */
    }
  }

  console.log("[corpus] fetching GHSA malware advisories...");
  const { ranges, advisoryCount, lastIso } = await fetchAllGhsaMalware(token);

  // Merge with any names previously curated (handwritten additions in older
  // schema or human-reviewed PRs). For pre-v2 corpus, add names with no range.
  if (Array.isArray(existing.names)) {
    for (const n of existing.names) {
      const lc = n.toLowerCase();
      if (!ranges.has(lc)) ranges.set(lc, new Set<string>());
    }
  }

  const sortedNames = [...ranges.keys()].sort();
  const rangesObj: Record<string, string[]> = {};
  for (const n of sortedNames) {
    const set = ranges.get(n) ?? new Set<string>();
    rangesObj[n] = [...set].sort();
  }

  const out: IocCorpus = {
    version: 2,
    fetchedAt: new Date().toISOString(),
    sources: { ghsa: { advisories: advisoryCount, lastIso } },
    names: sortedNames,
    ranges: rangesObj,
    scriptSha256: [...new Set([...(existing.scriptSha256 ?? []), ...SEED_SCRIPT_HASHES])].sort(),
    domains: [...new Set([...(existing.domains ?? []), ...SEED_DOMAINS])].sort(),
    wallets: [...new Set([...(existing.wallets ?? []), ...SEED_WALLETS])].sort(),
  };
  if (!existsSync(dirname(TARGET))) mkdirSync(dirname(TARGET), { recursive: true });
  writeFileSync(TARGET, JSON.stringify(out, null, 2) + "\n");
  let withRanges = 0;
  for (const r of Object.values(rangesObj)) if (r.length > 0) withRanges++;
  console.log(
    `[corpus] wrote ${TARGET}: ${out.names.length} names, ${withRanges} with explicit ranges, ${out.domains.length} domains`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
