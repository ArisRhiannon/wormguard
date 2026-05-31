#!/usr/bin/env bun
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Refresh the curated typosquat-target list (TOP_NAMES) from a real public
// source. We use ecosyste.ms — a public, ad-supported ecosystem index that
// exposes a "most depended on" ranking of npm packages. Source:
//   https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages
//   ?sort=dependent_packages_count&order=desc&per_page=100&page=N
//
// Output: data/top-names.json with provenance metadata. The TypeScript
// module src/top-names.ts re-exports that data.
//
// This script is the only network-touching code path for the typosquat
// reference set. The runtime audit pipeline does not contact the network.

import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";

const TARGET = "data/top-names.json";

interface EcosystemsPackage {
  name: string;
  dependent_packages_count?: number;
  ecosystem?: string;
}

const DELAY_MS = Number(process.env.WG_TOP_NAMES_DELAY_MS ?? 350);

async function fetchPage(page: number): Promise<EcosystemsPackage[]> {
  const url = `https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=dependent_packages_count&order=desc&per_page=100&page=${page}`;
  // Anonymous access to ecosyste.ms is rate-limited; rapid pagination causes
  // empty/429 responses. Retry with exponential backoff before giving up.
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, DELAY_MS * 2 ** attempt));
    const res = await fetch(url, {
      headers: { "user-agent": "wormguard-top-names-refresh", accept: "application/json" },
    });
    if (res.status === 429 || res.status >= 500) continue;
    if (!res.ok) throw new Error(`ecosyste.ms page ${page} failed: ${res.status} ${res.statusText}`);
    const arr = (await res.json()) as EcosystemsPackage[];
    if (Array.isArray(arr) && arr.length > 0) return arr;
    // Empty array on a page we know should be full ⇒ treat as throttle, retry.
  }
  return [];
}

async function fetchTopNames(targetCount: number): Promise<{ names: string[]; lastFetched: string }> {
  const collected = new Set<string>();
  let page = 1;
  const maxPages = Math.ceil(targetCount / 100) + 5;
  while (collected.size < targetCount && page <= maxPages) {
    const arr = await fetchPage(page);
    if (arr.length === 0) break; // exhausted (after retries) or end of data
    for (const p of arr) {
      if (typeof p?.name === "string") collected.add(p.name.toLowerCase());
    }
    if (arr.length < 100) break;
    page++;
    await new Promise((r) => setTimeout(r, DELAY_MS));
  }
  return {
    names: [...collected].sort(),
    lastFetched: new Date().toISOString(),
  };
}

async function main(): Promise<void> {
  // Configurable target (default 5000). A larger reference set of legitimately
  // popular packages is the primary lever for reducing typosquat/IoC-near false
  // positives: any scanned name present here is recognised as legit and skipped.
  const target = Number(process.env.WG_TOP_NAMES_COUNT ?? process.argv[2] ?? 5000);
  const { names, lastFetched } = await fetchTopNames(Number.isFinite(target) && target > 0 ? target : 5000);
  console.log(`[top-names] fetched ${names.length} most-depended-on npm packages`);
  const out = {
    version: 1,
    source: "https://packages.ecosyste.ms (npmjs.org, sort=dependent_packages_count desc)",
    fetchedAt: lastFetched,
    count: names.length,
    names,
  };
  if (!existsSync(dirname(TARGET))) mkdirSync(dirname(TARGET), { recursive: true });
  writeFileSync(TARGET, JSON.stringify(out, null, 2) + "\n");
  console.log(`[top-names] wrote ${TARGET}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
