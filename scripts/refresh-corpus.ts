// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Refresh the bundled IoC corpus from public sources.
//
//   1. GitHub Advisory Database (public REST endpoint, unauthenticated, but
//      authenticated requests get a higher rate limit). We pull every
//      advisory with `type=malware` and `ecosystem=npm`.
//   2. OSF malicious-packages OSV index (best-effort; we read the directory
//      listing via the GitHub API).
//
// The output is a deterministic JSON file at data/iocs.json with:
//   {
//     version: number,
//     fetchedAt: string,
//     sources: { ghsa: { count: number; lastIso: string } },
//     names: string[],            // alphabetically sorted, lowercase
//     scriptSha256: string[],     // sha256 of known-malicious lifecycle script bodies
//     domains: string[],          // C2 / exfiltration hostnames, lowercased
//     wallets: string[],          // crypto wallet addresses observed in payloads
//   }
//
// Network usage is opt-in: this script is the only place wormguard touches
// the network. The rest of the audit pipeline runs entirely offline against
// the bundled corpus.

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const TARGET = "data/iocs.json";

interface GhsaPackage {
  ecosystem: string;
  name: string;
}
interface GhsaVuln {
  package?: GhsaPackage;
}
interface GhsaAdvisory {
  ghsa_id?: string;
  type?: string;
  vulnerabilities?: GhsaVuln[];
  withdrawn_at?: string | null;
  published_at?: string | null;
  updated_at?: string | null;
}

async function fetchAllGhsaMalware(token?: string): Promise<{ names: Set<string>; lastIso: string }> {
  const names = new Set<string>();
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
      const vulns = a.vulnerabilities ?? [];
      for (const v of vulns) {
        if (v.package?.ecosystem === "npm" && typeof v.package.name === "string") {
          names.add(v.package.name.toLowerCase());
        }
      }
      if (a.published_at && a.published_at > lastIso) lastIso = a.published_at;
    }
    // Follow GitHub's Link: <...>; rel="next" header for cursor pagination.
    const link = res.headers.get("link") ?? "";
    const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
    url = nextMatch ? nextMatch[1] ?? null : null;
    if (url) await new Promise((r) => setTimeout(r, 250));
  }
  console.log(`[corpus] traversed ${pages} GHSA pages`);
  return { names, lastIso };
}

interface IocCorpus {
  version: number;
  fetchedAt: string;
  sources: {
    ghsa: { count: number; lastIso: string };
  };
  names: string[];
  scriptSha256: string[];
  domains: string[];
  wallets: string[];
}

const SEED_DOMAINS = [
  // Curated, public, well-attested supply-chain-attack exfil endpoints (subset)
  // sourced from public reports of the npm worm campaigns of 2025-2026.
  // This list is intentionally short; we err on the side of false negatives
  // until we can pull a maintained feed.
  "webhook.site",
  "discord.com/api/webhooks",
  "discordapp.com/api/webhooks",
  "telegram.org/bot",
  "api.telegram.org/bot",
  "ngrok-free.app",
  "trycloudflare.com",
];

const SEED_SCRIPT_HASHES: string[] = [
  // Reserved for known-malicious script SHA256s we accumulate from public
  // reports. Empty in seed; populated via human-reviewed PRs.
];

const SEED_WALLETS: string[] = [
  // Reserved for crypto wallet addresses observed in worm payloads (BTC/ETH).
  // Empty in seed.
];

async function main(): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.warn("[corpus] GITHUB_TOKEN unset; using anonymous rate limit (60/h).");
  }
  const existing: Partial<IocCorpus> = existsSync(TARGET)
    ? JSON.parse(readFileSync(TARGET, "utf8"))
    : {};

  console.log("[corpus] fetching GHSA malware advisories...");
  const { names, lastIso } = await fetchAllGhsaMalware(token);
  console.log(`[corpus] GHSA: ${names.size} malicious npm package names`);

  // Merge with any names previously in the file (hand-curated additions).
  for (const n of existing.names ?? []) names.add(n.toLowerCase());

  const out: IocCorpus = {
    version: 1,
    fetchedAt: new Date().toISOString(),
    sources: { ghsa: { count: names.size, lastIso } },
    names: [...names].sort(),
    scriptSha256: [...new Set([...(existing.scriptSha256 ?? []), ...SEED_SCRIPT_HASHES])].sort(),
    domains: [...new Set([...(existing.domains ?? []), ...SEED_DOMAINS])].sort(),
    wallets: [...new Set([...(existing.wallets ?? []), ...SEED_WALLETS])].sort(),
  };
  if (!existsSync(dirname(TARGET))) mkdirSync(dirname(TARGET), { recursive: true });
  writeFileSync(TARGET, JSON.stringify(out, null, 2) + "\n");
  console.log(`[corpus] wrote ${TARGET}: ${out.names.length} names, ${out.domains.length} domains`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
