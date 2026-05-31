// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// Resolve a shell command from package.json `scripts.{preinstall,install,postinstall,prepare}`
// into the set of *JavaScript sources* that will actually execute. We hand the parsing of
// the shell string to `shell-quote` (the same library used by webpack, vercel, etc.) instead
// of attempting to reinvent shell tokenization.
//
// Three execution shapes matter for forensics:
//   1.  `node ./build.js`             -> read & analyze ./build.js
//   2.  `node -e "require('https')..."` -> analyze the inline source
//   3.  `node -e "$NODE_OPTS" foo`     -> we cannot follow env var expansion; we record
//                                        the residual source as suspicious.
//
// We deliberately do not exec anything: this is a forensic reader, not a runner.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve, isAbsolute } from "node:path";
import { parse as shellParse } from "shell-quote";

export interface InvokedSource {
  /** Absolute path of the JS file (or pseudo-path "<inline>") that will execute. */
  file: string;
  /** Source text. */
  source: string;
  /** True if the source came from a `node -e`/`--eval`/`-p`/`--print` argument. */
  inline: boolean;
  /** Why this source was selected (for the report). */
  reason: string;
}

/** Result of analyzing a shell command line. */
export interface ShellResolution {
  /** Concrete sources that will execute (resolved relative to `pkgRoot`). */
  sources: InvokedSource[];
  /** Raw evidence indicators found at the *shell* level (curl|sh, wget, base64 -d, etc.). */
  shellHits: Array<{ category: ShellCategory; evidence: string }>;
  /** True if the parser bailed and we fell back to substring scanning. */
  shellParseFallback: boolean;
}

export type ShellCategory =
  | "shell-pipe-to-shell" /* `... | sh` style */
  | "network-fetch-tool" /* curl, wget, fetch (CLI), iwr, ncat, telnet, nc */
  | "shell-base64-decode" /* `base64 -d`, `openssl base64 -d` */
  | "shell-eval" /* `eval ...` at shell level */
  | "shell-write-secret" /* writing into ~/.npmrc, ~/.aws, ~/.ssh, /tmp/* with secrets... */
  | "non-node-binary" /* command does not start with node-y binary; suspicious in install scripts */;

const SHELL_PIPE_RE = /\|\s*(?:sh|bash|zsh|dash|ksh|powershell|pwsh)(?:\s|$)/i;
const NETWORK_TOOL_RE = /\b(?:curl|wget|nc|ncat|telnet|invoke-webrequest|iwr)\b/i;
const SHELL_B64_RE = /\b(?:base64\s+(?:-d|--decode)|openssl\s+(?:base64|enc)\s+-d)\b/i;
const SHELL_EVAL_RE = /(?:^|[\s;&|`])(?:eval|source)\s/i;

export interface ShellResolveOptions {
  /** Maximum file size (bytes) we will read; larger files are skipped to avoid DoS. */
  maxFileBytes?: number;
}

const DEFAULT_MAX_BYTES = 2_000_000;

function readBoundedSync(path: string, maxBytes: number): string | null {
  try {
    const st = statSync(path);
    if (!st.isFile()) return null;
    if (st.size > maxBytes) return null;
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

interface CmdAndArgs {
  cmd: string;
  args: string[];
  /** Original raw string segment for evidence. */
  raw: string;
}

/**
 * Tokenize the entire command line and split into argv groups separated by
 * shell control operators. Each group is a separate command. We keep the
 * already-tokenized argv form rather than rejoining with spaces (which would
 * lose the quoting and corrupt inline `node -e "..."` sources).
 */
function tokenizedCommands(line: string): CmdAndArgs[] {
  const tokens = shellParse(line);
  const out: CmdAndArgs[] = [];
  let buf: string[] = [];
  const flush = (raw: string): void => {
    if (buf.length === 0) return;
    out.push({ cmd: buf[0] as string, args: buf.slice(1), raw });
    buf = [];
  };
  for (const t of tokens) {
    if (typeof t === "object" && t !== null && "op" in t) {
      const op = (t as { op: string }).op;
      if (op === "&&" || op === "||" || op === "|" || op === ";") {
        flush(buf.join(" "));
        continue;
      }
      // glob, $variable, redirection — skip for splitting
      continue;
    }
    if (typeof t === "string") {
      buf.push(t);
    } else if (typeof t === "object" && t !== null && "pattern" in t) {
      buf.push((t as { pattern: string }).pattern);
    }
  }
  flush(buf.join(" "));
  return out;
}

function isNodeBinary(name: string): boolean {
  const base = name.toLowerCase();
  return (
    base === "node" ||
    base === "nodejs" ||
    base.endsWith("/node") ||
    base.endsWith("/nodejs") ||
    base === "ts-node" ||
    base.endsWith("/ts-node") ||
    base === "bun" ||
    base.endsWith("/bun") ||
    base === "deno" ||
    base.endsWith("/deno")
  );
}

/**
 * Given a `node ...` argv, find either the inline source (`-e` / `--eval` / `-p` / `--print`)
 * or the script file argument. Returns null if we cannot determine.
 */
function resolveNodeArgv(args: string[]): { inline?: string; script?: string } | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "-e" || a === "--eval" || a === "-p" || a === "--print") {
      const next = args[i + 1];
      if (typeof next === "string") return { inline: next };
      return null;
    }
    if (a.startsWith("--eval=")) return { inline: a.slice("--eval=".length) };
    if (a.startsWith("--print=")) return { inline: a.slice("--print=".length) };
    if (a.startsWith("-")) continue; // skip other flags
    return { script: a };
  }
  return null;
}

/** Resolve a single shell command line against a package root. */
export function resolveShellCommand(
  pkgRoot: string,
  command: string,
  opts: ShellResolveOptions = {}
): ShellResolution {
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_BYTES;
  const out: ShellResolution = { sources: [], shellHits: [], shellParseFallback: false };

  // Shell-level indicators on the raw command (these flag suspicious shell behavior
  // even when no node script is invoked).
  if (SHELL_PIPE_RE.test(command)) {
    out.shellHits.push({ category: "shell-pipe-to-shell", evidence: command.slice(0, 200) });
  }
  if (NETWORK_TOOL_RE.test(command)) {
    out.shellHits.push({ category: "network-fetch-tool", evidence: command.slice(0, 200) });
  }
  if (SHELL_B64_RE.test(command)) {
    out.shellHits.push({ category: "shell-base64-decode", evidence: command.slice(0, 200) });
  }
  if (SHELL_EVAL_RE.test(command)) {
    out.shellHits.push({ category: "shell-eval", evidence: command.slice(0, 200) });
  }

  let parts: CmdAndArgs[];
  try {
    parts = tokenizedCommands(command);
  } catch {
    out.shellParseFallback = true;
    parts = [];
  }

  for (const tokens of parts) {
    if (!isNodeBinary(tokens.cmd)) {
      // A non-node binary in an install script doesn't always mean malicious;
      // we leave that classification to the rule engine which can downgrade
      // for known-good binaries (npm, yarn, pnpm, node-gyp, prebuild-install...).
      continue;
    }
    const resolved = resolveNodeArgv(tokens.args);
    if (!resolved) continue;
    if (typeof resolved.inline === "string") {
      out.sources.push({
        file: "<inline>",
        source: resolved.inline,
        inline: true,
        reason: `inline node -e/--eval in ${tokens.cmd}`,
      });
      continue;
    }
    if (typeof resolved.script === "string") {
      const target = resolved.script;
      const candidate = isAbsolute(target) ? target : resolve(pkgRoot, target);
      if (existsSync(candidate)) {
        const text = readBoundedSync(candidate, maxBytes);
        if (text !== null) {
          out.sources.push({
            file: candidate,
            source: text,
            inline: false,
            reason: `argv script ${target}`,
          });
        }
      }
    }
  }

  return out;
}

/** Resolve all lifecycle scripts for a package root. */
export function resolvePackageLifecycle(
  pkgRoot: string,
  scripts: Partial<Record<"preinstall" | "install" | "postinstall" | "prepare", string>>,
  opts: ShellResolveOptions = {}
): { lifecycle: string; resolution: ShellResolution }[] {
  const out: { lifecycle: string; resolution: ShellResolution }[] = [];
  for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"] as const) {
    const cmd = scripts[lifecycle];
    if (typeof cmd !== "string" || cmd.length === 0) continue;
    out.push({ lifecycle, resolution: resolveShellCommand(pkgRoot, cmd, opts) });
  }
  // Also try to read commonly-named install entry files even if no lifecycle is declared,
  // because attackers sometimes drop an install.js and rely on prepublishOnly/scripts side-effects.
  for (const candidate of ["install.js", "scripts/install.js", "lib/install.js", "preinstall.js"]) {
    const p = join(pkgRoot, candidate);
    if (existsSync(p)) {
      const text = readBoundedSync(p, opts.maxFileBytes ?? DEFAULT_MAX_BYTES);
      if (text !== null) {
        out.push({
          lifecycle: "implicit",
          resolution: {
            sources: [
              {
                file: p,
                source: text,
                inline: false,
                reason: `implicit install file ${candidate}`,
              },
            ],
            shellHits: [],
            shellParseFallback: false,
          },
        });
      }
    }
  }
  return out;
}
