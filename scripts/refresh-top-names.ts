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

async function fetchTopNames(targetCount: number): Promise<{ names: string[]; lastFetched: string }> {
  const collected = new Set<string>();
  let page = 1;
  while (collected.size < targetCount && page <= 50) {
    const url = `https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=dependent_packages_count&order=desc&per_page=100&page=${page}`;
    const res = await fetch(url, {
      headers: { "user-agent": "wormguard-top-names-refresh", accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`ecosyste.ms page ${page} failed: ${res.status} ${res.statusText}`);
    }
    const arr = (await res.json()) as EcosystemsPackage[];
    if (!Array.isArray(arr) || arr.length === 0) break;
    for (const p of arr) {
      if (typeof p?.name === "string") collected.add(p.name.toLowerCase());
    }
    if (arr.length < 100) break;
    page++;
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    names: [...collected].sort().slice(0, targetCount),
    lastFetched: new Date().toISOString(),
  };
}

async function main(): Promise<void> {
  const { names, lastFetched } = await fetchTopNames(500);
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
