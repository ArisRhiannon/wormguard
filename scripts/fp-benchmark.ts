#!/usr/bin/env bun
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// False-positive benchmark.
//
// Installs a fixed set of widely-used, known-clean npm packages (resolving the
// full transitive tree) and runs `scan()` against it. Because every package in
// the tree is legitimate, ANY critical/high finding is a false positive — the
// kind that breaks a real project's CI and erodes trust. This script reports
// the measured FP rate by severity and exits non-zero if any critical/high
// false positive is found, so it doubles as a regression guard.
//
// Usage:
//   bun run scripts/fp-benchmark.ts                # install pinned set, scan
//   bun run scripts/fp-benchmark.ts /path/to/proj  # scan an existing tree
//
// Network: only the install step touches the network (npm). The scan itself is
// fully offline. The fixed set is intentionally heavy on packages with
// legitimate lifecycle scripts (esbuild, sharp, prisma, better-sqlite3, bcrypt,
// husky, @swc/core, …) since those are the hardest false-positive cases.

import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scan } from "../src/index";

// Pinned dependency set. Mix of pure-JS popular packages and native-build
// packages with legitimate install/prepare scripts.
const DEPS: Record<string, string> = {
  react: "^18.3.1",
  "react-dom": "^18.3.1",
  express: "^4.21.2",
  lodash: "^4.17.21",
  axios: "^1.7.9",
  chalk: "^5.4.1",
  vue: "^3.5.13",
  vite: "^6.0.7",
  esbuild: "^0.24.2",
  typescript: "^5.7.2",
  webpack: "^5.97.1",
  eslint: "^9.17.0",
  prettier: "^3.4.2",
  jest: "^29.7.0",
  "better-sqlite3": "^11.7.0",
  bcrypt: "^5.1.1",
  husky: "^9.1.7",
  prisma: "^6.1.0",
  "@swc/core": "^1.10.4",
  nodemon: "^3.1.9",
};

function installTree(): string {
  const dir = mkdtempSync(join(tmpdir(), "wg-fp-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "wg-fp-benchmark", version: "1.0.0", private: true, dependencies: DEPS }, null, 2),
  );
  console.log(`[fp-benchmark] installing ${Object.keys(DEPS).length} direct deps (full tree, --ignore-scripts)…`);
  execSync("npm install --ignore-scripts --no-audit --no-fund --loglevel=error", { cwd: dir, stdio: "inherit" });
  return dir;
}

function countTreePackages(dir: string): number {
  try {
    return Number(execSync(`find "${dir}/node_modules" -name package.json -maxdepth 3 | wc -l`).toString().trim());
  } catch {
    return -1;
  }
}

function main(): void {
  const argDir = process.argv[2];
  const dir = argDir ?? installTree();
  const total = countTreePackages(dir);
  const { findings, counts } = scan(dir);

  const gating = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  console.log("\n=== wormguard false-positive benchmark ===");
  console.log(`tree packages (approx): ${total}`);
  console.log(`findings by severity:   ${JSON.stringify(counts)}`);
  console.log(`CI-gating findings (critical+high): ${gating.length}`);
  if (gating.length > 0) {
    console.log("\nCI-gating false positives (every package here is known-clean):");
    for (const f of gating) console.log(`  ${f.severity} ${f.ruleId} ${f.pkg}: ${f.message}`);
  }
  const medium = findings.filter((f) => f.severity === "medium");
  if (medium.length > 0) {
    console.log("\nmedium findings (informational, non-gating):");
    for (const f of medium) console.log(`  ${f.ruleId} ${f.pkg}: ${f.message}`);
  }

  if (!argDir) rmSync(dir, { recursive: true, force: true });

  if (gating.length > 0) {
    console.error(`\n[fp-benchmark] FAIL: ${gating.length} critical/high false positive(s) on a known-clean tree.`);
    process.exit(1);
  }
  console.log("\n[fp-benchmark] PASS: zero critical/high false positives on the clean tree.");
}

main();
