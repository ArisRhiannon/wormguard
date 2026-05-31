#!/usr/bin/env bun
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Populate `data/script-allowlist.json` by reading the npm registry packument
// for a curated list of widely-used packages with legitimate lifecycle scripts.
//
// We hash the lifecycle-script *body strings* (the value of
// `scripts.{preinstall,install,postinstall,prepare}` in package.json), not the
// referenced JS files. Hashing the body string is the cheapest, most stable
// fingerprint: a Shai-Hulud-style attacker who replaces only the underlying
// `install.js` will be caught by the AST analyzer; an attacker who changes
// the body string to call out to a different file or inline payload is
// caught by THIS allowlist (script-fingerprint drift).
//
// Usage:
//   GITHUB_TOKEN=...  bun run scripts/populate-allowlist.ts
//
// Network usage: opt-in. The runtime audit pipeline never touches the network.

import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

const TARGET = "data/script-allowlist.json";

/** Curated list of packages with legitimate lifecycle scripts that are commonly
 *  flagged by naive scanners (the false-positive set called out in the
 *  user's critique #3). We pull every published version's lifecycle scripts
 *  and aggregate every distinct body hash. */
const POPULAR_LIFECYCLE_PACKAGES = [
  // Native binaries / build tooling — the long tail of "things with postinstall"
  "esbuild",
  "@esbuild/linux-x64",
  "@esbuild/darwin-x64",
  "@esbuild/darwin-arm64",
  "@esbuild/win32-x64",
  "sharp",
  "@img/sharp-libvips-linux-x64",
  "@img/sharp-libvips-darwin-x64",
  "@img/sharp-linux-x64",
  "node-sass",
  "sass-embedded",
  "node-gyp",
  "node-gyp-build",
  "prebuild-install",
  "node-pre-gyp",
  "@mapbox/node-pre-gyp",
  "bcrypt",
  "argon2",
  "canvas",
  "sqlite3",
  "better-sqlite3",
  "fsevents",
  "leveldown",
  "lmdb",
  "robotjs",
  "puppeteer",
  "puppeteer-core",
  "playwright",
  "playwright-core",
  "@playwright/test",
  "playwright-chromium",
  "playwright-firefox",
  "playwright-webkit",
  "electron",
  "electron-builder",
  "@electron/rebuild",
  "cypress",
  "msnodesqlv8",
  "node-addon-api",
  "nodemon",
  "ws",
  "websocket",
  "node-rdkafka",
  "kerberos",
  "snappy",
  "node-zstd",
  "isomorphic-zstd",
  "tree-sitter",
  "duckdb",
  "@duckdb/node-api",
  "@parcel/watcher",
  "@swc/core",
  "@swc/wasm",
  "@biomejs/biome",
  "rollup",
  "@rollup/rollup-linux-x64-gnu",
  "@rollup/rollup-darwin-arm64",
  "@rollup/rollup-darwin-x64",
  "@next/swc-linux-x64-gnu",
  "@next/swc-darwin-arm64",
  "@next/swc-darwin-x64",
  "next",
  "lightningcss",
  "@tailwindcss/oxide-linux-x64-gnu",
  "@tailwindcss/oxide-darwin-arm64",
  "@tailwindcss/oxide-darwin-x64",
  "tailwindcss",
  "vite",
  "@parcel/core",
  "parcel",
  "turbo",
  "wasm-pack",
  // ORM / build / codegen with prepare/postinstall
  "prisma",
  "@prisma/client",
  "@prisma/engines",
  "drizzle-kit",
  "kysely",
  "pg-native",
  "node-libcurl",
  "ssh2",
  "@aws-sdk/client-s3",
  "ws-native",
  // Hooks
  "husky",
  "simple-git-hooks",
  "lefthook",
  "lint-staged",
  // CLI helpers
  "patch-package",
  "is-installed-globally",
  "core-js",
  "core-js-pure",
  "regenerator-runtime",
  "@protobufjs/inquire",
  // Cypress / browser
  "cypress-image-snapshot",
  "geckodriver",
  "chromedriver",
  "phantomjs-prebuilt",
  // Postinstall-warning patterns
  "create-react-app",
  "create-vite",
  "create-next-app",
  // Toolchains
  "ts-node",
  "tsx",
  "@types/node",
  "deasync",
  "websocket-driver",
  "iconv",
  "node-tar",
  "wabt",
  "binaryen",
];

const LIFECYCLE_KEYS = ["preinstall", "install", "postinstall", "prepare"] as const;

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

interface Packument {
  versions?: Record<string, { scripts?: Record<string, unknown>; deprecated?: unknown }>;
}

async function fetchPackument(name: string, token?: string): Promise<Packument | null> {
  const headers: Record<string, string> = { "user-agent": "wormguard-allowlist-populator" };
  if (token) headers.authorization = `Bearer ${token}`;
  const url = `https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`;
  const res = await fetch(url, { headers });
  if (!res.ok) return null;
  return (await res.json()) as Packument;
}

interface Allowlist {
  version: number;
  generatedAt: string;
  packages: Record<string, string[]>;
  /** Audit trail: for each hash, the script string and the versions seen. */
  origins: Record<string, { hash: string; lifecycle: string; body: string; versionCount: number }[]>;
}

async function main(): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  const out: Allowlist = {
    version: 1,
    generatedAt: new Date().toISOString(),
    packages: {},
    origins: {},
  };

  for (const pkg of POPULAR_LIFECYCLE_PACKAGES) {
    process.stdout.write(`[allowlist] ${pkg} ... `);
    let pack: Packument | null = null;
    try {
      pack = await fetchPackument(pkg, token);
    } catch (err) {
      console.log(`fetch error: ${(err as Error).message}`);
      continue;
    }
    if (!pack || !pack.versions) {
      console.log("no packument");
      continue;
    }
    const seenHashes = new Set<string>();
    const origins: { hash: string; lifecycle: string; body: string; versionCount: number }[] = [];
    const counts = new Map<string, number>();
    for (const [version, meta] of Object.entries(pack.versions)) {
      if (!meta || typeof meta !== "object") continue;
      if (meta.deprecated) continue; // skip deprecated versions (don't fingerprint compromised ones)
      const scripts = meta.scripts ?? {};
      for (const lc of LIFECYCLE_KEYS) {
        const body = scripts[lc];
        if (typeof body !== "string" || body.length === 0) continue;
        const h = sha256(body);
        const counterKey = `${h}|${lc}`;
        counts.set(counterKey, (counts.get(counterKey) ?? 0) + 1);
        if (!seenHashes.has(h)) {
          seenHashes.add(h);
          origins.push({ hash: h, lifecycle: lc, body, versionCount: 0 });
        }
      }
      void version;
    }
    if (seenHashes.size === 0) {
      console.log("no lifecycle scripts");
      continue;
    }
    // Fill in version counts.
    for (const o of origins) {
      o.versionCount = counts.get(`${o.hash}|${o.lifecycle}`) ?? 0;
    }
    // Filter: only retain hashes seen in at least 1 version (i.e., everything;
    // we keep the count as audit metadata).
    out.packages[pkg] = origins.map((o) => o.hash);
    out.origins[pkg] = origins;
    console.log(`${seenHashes.size} unique lifecycle script hashes`);
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!existsSync(dirname(TARGET))) mkdirSync(dirname(TARGET), { recursive: true });
  writeFileSync(TARGET, JSON.stringify(out, null, 2) + "\n");
  console.log(
    `[allowlist] wrote ${TARGET}: ${Object.keys(out.packages).length} packages, ${
      Object.values(out.packages).reduce((acc, v) => acc + v.length, 0)
    } total fingerprints`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
