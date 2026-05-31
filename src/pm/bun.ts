// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// bun.lock parser. Bun's textual lockfile (`bun.lock`, introduced in Bun 1.2)
// is JSONC: JSON with comments and trailing commas. The structure is roughly:
//
//   {
//     "lockfileVersion": 1,
//     "packages": {
//       "<name>": ["<name>@<version>", "<resolved-tarball>", { ... }, "<integrity>"]
//       ...
//     },
//     "workspaces": { ... }
//   }
//
// We tolerate JSONC by stripping `//` and `/* ... */` comments before JSON.parse.
//
// Bun's binary lockfile (bun.lockb) is NOT supported here; users should run
// `bun install --save-text-lockfile` once to convert. We still detect the
// presence of bun.lockb and emit a friendly error.

import { type PackageRecord, WormguardError } from "../types";

interface BunLockfile {
  lockfileVersion?: number;
  packages?: Record<string, unknown[]>;
  workspaces?: Record<string, unknown>;
}

function stripJsonComments(text: string): string {
  let out = "";
  let i = 0;
  let inStr = false;
  let strCh = "";
  while (i < text.length) {
    const ch = text[i];
    const nx = text[i + 1];
    if (inStr) {
      out += ch;
      if (ch === "\\" && i + 1 < text.length) {
        out += nx;
        i += 2;
        continue;
      }
      if (ch === strCh) inStr = false;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = true;
      strCh = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === "/" && nx === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && nx === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += ch;
    i++;
  }
  // remove trailing commas before } or ]
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function hostOf(resolved: string | null): string | null {
  if (!resolved) return null;
  try {
    return new URL(resolved).host || null;
  } catch {
    return null;
  }
}

const NAME_VERSION_RE = /^(@[^/]+\/[^@]+|[^@]+)@(.+)$/;

export function parseBunLockfile(text: string, isBinary = false): PackageRecord[] {
  if (isBinary) {
    throw new WormguardError(
      "bun.lockb (binary) is unsupported; run `bun install --save-text-lockfile` to generate bun.lock",
    );
  }
  let json: BunLockfile;
  try {
    json = JSON.parse(stripJsonComments(text)) as BunLockfile;
  } catch (err) {
    throw new WormguardError(`invalid bun.lock JSON: ${(err as Error).message}`);
  }
  if (!json || typeof json !== "object") throw new WormguardError("bun.lock is not an object");
  if (!json.packages || typeof json.packages !== "object") return [];
  const out = new Map<string, PackageRecord>();
  for (const [_pkgKey, tuple] of Object.entries(json.packages)) {
    if (!Array.isArray(tuple) || tuple.length < 1) continue;
    const id = typeof tuple[0] === "string" ? tuple[0] : "";
    const m = NAME_VERSION_RE.exec(id);
    if (!m || !m[1] || !m[2]) continue;
    const name = m[1];
    const version = m[2];
    const resolved = typeof tuple[1] === "string" ? tuple[1] : null;
    // Bun stores integrity as the last string element when present
    let integrity: string | null = null;
    for (let k = tuple.length - 1; k >= 0; k--) {
      const v = tuple[k];
      if (typeof v === "string" && v.startsWith("sha")) {
        integrity = v;
        break;
      }
    }
    const cacheKey = `${name}@${version}`;
    if (out.has(cacheKey)) continue;
    out.set(cacheKey, {
      name,
      version,
      resolved,
      integrity,
      registryHost: hostOf(resolved),
      hasInstallScript: false, // bun lockfile does not record this; node_modules walker fills it.
      dev: false,
      packageManager: "bun",
    });
  }
  return [...out.values()];
}
