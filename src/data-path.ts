// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Resolve bundled data files (data/iocs.json, data/script-allowlist.json,
// data/top-names.json, data/npm-registry-keys.json) regardless of whether
// the caller is running from:
//
//   - source layout (src/corpus/iocs.ts -> ../../data/iocs.json)
//   - bundled output (dist/index.js     -> ../data/iocs.json)
//   - npm-installed package (node_modules/wormguard/dist/index.js -> ../data/iocs.json)
//
// We try a list of candidate paths relative to `import.meta.url` and
// return the first one that exists.

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

/**
 * Resolve a bundled data path. Pass the caller's `import.meta.url` and
 * the data file's basename (e.g. "iocs.json") and we walk up a few
 * directory levels looking for `data/<name>`.
 */
export function resolveDataPath(callerUrl: string, name: string): string {
  const here = dirname(fileURLToPath(callerUrl));
  // Try ./data, ../data, ../../data, ../../../data — covers source,
  // dist (single-level), dist/corpus (two-level after bundling), and
  // npm node_modules/wormguard/dist layouts.
  const candidates = [
    join(here, "data", name),
    join(here, "..", "data", name),
    join(here, "..", "..", "data", name),
    join(here, "..", "..", "..", "data", name),
  ];
  for (const c of candidates) {
    const abs = resolve(c);
    if (existsSync(abs)) return abs;
  }
  // Last resort: return the most-likely candidate so callers can read+throw
  // a deterministic ENOENT instead of looping further.
  return resolve(candidates[1] as string);
}
