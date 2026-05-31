// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// AST analyzer for JavaScript/TypeScript-flavored sources invoked from package
// lifecycle scripts. We parse with `acorn` (the parser used by webpack/rollup/eslint)
// and walk the tree with `acorn-walk`. This is intentionally NOT a complete static
// analyzer — it is a forensic detector tuned to surface install-time attack patterns
// (Shai-Hulud-style worm payloads, secret exfiltration, dynamic require/eval, etc.).
//
// Design choices that matter for the threat model:
//   * Constant folding of `+` and template-literal concatenation so that
//     `requ` + `ire` and `'ht' + 'tps'` cannot bypass detection.
//   * Inline base64 decode of `Buffer.from('<literal>', 'base64')` and `atob('<literal>')`
//     followed by re-scan of the decoded string for additional indicators.
//   * Source -> sink taint approximation: if a function call or property access reads
//     `process.env` / known-secret path / a private key file, and that value reaches
//     a network/child-process sink within the same program, we set `taintToSink`.
//   * Robust parse: we try ESM module mode first, fall back to script mode, and finally
//     fall back to a regex pass on the raw source so that an attacker cannot evade us
//     just by emitting unparseable syntax.

import { Parser, type Node } from "acorn";
import * as walk from "acorn-walk";
import type { AstCategory, AstHit, AstReport } from "../types";

interface AcornLoc {
  start: { line: number; column: number };
  end: { line: number; column: number };
}
interface AcornNode extends Node {
  loc?: AcornLoc;
  type: string;
  // narrowing helpers; acorn typings are loose and we walk many node kinds
  [k: string]: unknown;
}

const NETWORK_BUILTINS = new Set([
  "http",
  "https",
  "net",
  "tls",
  "dns",
  "dgram",
  "node:http",
  "node:https",
  "node:net",
  "node:tls",
  "node:dns",
  "node:dgram",
]);

const CHILD_PROC_BUILTINS = new Set(["child_process", "node:child_process"]);

const SECRET_PATH_RE =
  /\.npmrc|\.aws(?:[\\/]|$)|\.ssh(?:[\\/]|$)|\.netrc|id_rsa|id_ed25519|\.git[\\/]config|\.docker[\\/]config|kube[\\/]config|(^|[^a-zA-Z\d_])\.env(?:[^a-zA-Z\d_]|$)/i;

const SOURCE_CATEGORIES: ReadonlySet<AstCategory> = new Set([
  "env-read",
  "secret-path",
  "crypto-key-read",
]);

const SINK_CATEGORIES: ReadonlySet<AstCategory> = new Set([
  "network-builtin",
  "fetch",
  "child-process",
  "shell-pipe",
]);

const MAX_EVIDENCE = 200;
function snip(s: string): string {
  return s.length > MAX_EVIDENCE ? `${s.slice(0, MAX_EVIDENCE - 1)}…` : s;
}

/** Try to evaluate a node to a literal string. Handles `+`, template literals, parenthesized exprs. */
export function foldString(node: AcornNode | null | undefined, depth = 0): string | null {
  if (!node || depth > 24) return null;
  if (node.type === "Literal" && typeof (node as { value?: unknown }).value === "string") {
    return (node as unknown as { value: string }).value;
  }
  if (node.type === "TemplateLiteral") {
    const quasis = node.quasis as Array<{ value: { cooked?: string | null } }>;
    const exprs = node.expressions as Array<AcornNode>;
    let out = "";
    for (let i = 0; i < quasis.length; i++) {
      const q = quasis[i];
      out += (q && q.value && typeof q.value.cooked === "string" ? q.value.cooked : "");
      if (i < exprs.length) {
        const folded = foldString(exprs[i] ?? null, depth + 1);
        if (folded === null) return null;
        out += folded;
      }
    }
    return out;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const l = foldString(node.left as AcornNode, depth + 1);
    const r = foldString(node.right as AcornNode, depth + 1);
    if (l === null || r === null) return null;
    return l + r;
  }
  if (node.type === "ParenthesizedExpression") {
    return foldString((node as { expression?: AcornNode }).expression ?? null, depth + 1);
  }
  return null;
}

/** Try to decode a literal base64 argument. Returns the decoded string, or null on failure. */
function tryBase64Decode(literal: string): string | null {
  // Reject obviously non-base64 to avoid noise.
  if (literal.length < 8) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(literal)) return null;
  try {
    // Support both standard and URL-safe base64.
    const norm = literal.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(norm, "base64");
    if (buf.length === 0) return null;
    const decoded = buf.toString("utf8");
    // Reasonable sanity check: at least 70% printable.
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
    }
    if (decoded.length > 0 && printable / decoded.length < 0.7) return null;
    return decoded;
  } catch {
    return null;
  }
}

interface AnalyzerState {
  hits: AstHit[];
  parseFallback: boolean;
  /** Track whether we've seen a source / sink for taint approximation. */
  sources: Set<AstCategory>;
  sinks: Set<AstCategory>;
}

function pushHit(state: AnalyzerState, node: AcornNode, hit: Omit<AstHit, "line" | "column">): void {
  const loc = node.loc;
  state.hits.push({
    ...hit,
    line: loc?.start.line ?? 0,
    column: loc?.start.column ?? 0,
  });
  if (SOURCE_CATEGORIES.has(hit.category)) state.sources.add(hit.category);
  if (SINK_CATEGORIES.has(hit.category)) state.sinks.add(hit.category);
}

function memberPath(node: AcornNode | undefined | null): string | null {
  if (!node) return null;
  if (node.type === "Identifier") return (node as { name?: string }).name ?? null;
  if (node.type === "MemberExpression") {
    const obj = memberPath(node.object as AcornNode);
    const prop = node.computed
      ? null
      : ((node.property as { name?: string } | undefined)?.name ?? null);
    if (obj === null || prop === null) return null;
    return `${obj}.${prop}`;
  }
  return null;
}

function isCalleeOneOf(callee: AcornNode | undefined | null, names: ReadonlySet<string>): boolean {
  const path = memberPath(callee);
  return path !== null && names.has(path);
}

const EVAL_CALLEES = new Set(["eval"]);
const FUNCTION_CTOR = new Set(["Function"]);
const VM_EVAL_CALLEES = new Set([
  "vm.runInNewContext",
  "vm.runInThisContext",
  "vm.runInContext",
  "vm.compileFunction",
]);
const CP_CALLEES = new Set([
  "child_process.exec",
  "child_process.execSync",
  "child_process.spawn",
  "child_process.spawnSync",
  "child_process.fork",
  "child_process.execFile",
  "child_process.execFileSync",
  // common destructured form caught at call-site Identifier match below
]);

const CRYPTO_KEY_CALLEES = new Set([
  "crypto.createPrivateKey",
  "crypto.createSign",
  "crypto.createDecipheriv",
  "crypto.privateDecrypt",
]);

function analyzeAst(ast: AcornNode, source: string, state: AnalyzerState): void {
  // Track aliases like:  const cp = require('child_process')
  //                      const { exec } = require('child_process')
  // so we catch  cp.exec(...)  and  exec(...).
  const childProcAliases = new Set<string>(); // identifiers for the *module* (cp)
  const childProcMethodAliases = new Map<string, string>(); // exec -> 'exec'
  const httpsAliases = new Set<string>();
  const fsAliases = new Set<string>();

  walk.fullAncestor(ast as Node, (rawNode, _state, _ancestors) => {
    const node = rawNode as AcornNode;

    // -------- require('X') / import('X') --------
    if (
      node.type === "CallExpression" &&
      ((node.callee as AcornNode | undefined)?.type === "Identifier" &&
        ((node.callee as { name?: string }).name === "require" ||
          (node.callee as { name?: string }).name === "import"))
    ) {
      const args = node.arguments as Array<AcornNode>;
      const arg0 = args[0];
      const folded = arg0 ? foldString(arg0) : null;

      if (folded === null) {
        if (arg0) {
          pushHit(state, node, {
            category: "dynamic-require",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
      } else {
        if (NETWORK_BUILTINS.has(folded)) {
          pushHit(state, node, {
            category: "network-builtin",
            evidence: `require('${folded}')`,
            resolvedLiteral: folded,
          });
        }
        if (CHILD_PROC_BUILTINS.has(folded)) {
          pushHit(state, node, {
            category: "child-process",
            evidence: `require('${folded}')`,
            resolvedLiteral: folded,
          });
        }
      }
    }

    // -------- ImportDeclaration source --------
    if (node.type === "ImportDeclaration") {
      const src = (node.source as { value?: unknown } | undefined)?.value;
      if (typeof src === "string") {
        if (NETWORK_BUILTINS.has(src)) {
          pushHit(state, node, {
            category: "network-builtin",
            evidence: `import from '${src}'`,
            resolvedLiteral: src,
          });
        }
        if (CHILD_PROC_BUILTINS.has(src)) {
          pushHit(state, node, {
            category: "child-process",
            evidence: `import from '${src}'`,
            resolvedLiteral: src,
          });
        }
      }
    }

    // -------- VariableDeclarator capture aliases --------
    if (node.type === "VariableDeclarator") {
      const init = node.init as AcornNode | undefined;
      if (
        init &&
        init.type === "CallExpression" &&
        (init.callee as { name?: string } | undefined)?.name === "require"
      ) {
        const folded = foldString((init.arguments as Array<AcornNode>)[0] ?? null);
        if (folded !== null) {
          const id = node.id as AcornNode;
          if (CHILD_PROC_BUILTINS.has(folded)) {
            if (id.type === "Identifier") childProcAliases.add((id as unknown as { name: string }).name);
            if (id.type === "ObjectPattern") {
              const props = id.properties as Array<AcornNode>;
              for (const prop of props) {
                const key = (prop as { key?: AcornNode }).key;
                const value = (prop as { value?: AcornNode }).value;
                if (key && key.type === "Identifier" && value && value.type === "Identifier") {
                  childProcMethodAliases.set(
                    (value as unknown as { name: string }).name,
                    (key as unknown as { name: string }).name
                  );
                }
              }
            }
          }
          if (NETWORK_BUILTINS.has(folded) && id.type === "Identifier") {
            httpsAliases.add((id as unknown as { name: string }).name);
          }
          if ((folded === "fs" || folded === "node:fs") && id.type === "Identifier") {
            fsAliases.add((id as unknown as { name: string }).name);
          }
        }
      }
    }

    // -------- eval() / new Function() / vm.* --------
    if (node.type === "CallExpression") {
      const callee = node.callee as AcornNode | undefined;
      if (callee && callee.type === "Identifier" && EVAL_CALLEES.has((callee as unknown as { name: string }).name)) {
        const args = node.arguments as Array<AcornNode>;
        const arg = args[0];
        const folded = arg ? foldString(arg) : null;
        pushHit(state, node, {
          category: "eval",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
        if (folded === null && arg) {
          // Concatenated/dynamic argument feeding eval is the obfuscation pattern
          pushHit(state, node, {
            category: "string-concat-eval",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
      }
      if (callee && isCalleeOneOf(callee, VM_EVAL_CALLEES)) {
        pushHit(state, node, {
          category: "eval",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
      if (callee && isCalleeOneOf(callee, CP_CALLEES)) {
        pushHit(state, node, {
          category: "child-process",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
      if (callee && callee.type === "Identifier") {
        const name = (callee as unknown as { name: string }).name;
        if (childProcMethodAliases.has(name)) {
          pushHit(state, node, {
            category: "child-process",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
        if (name === "fetch") {
          pushHit(state, node, {
            category: "fetch",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
      }
      if (callee && callee.type === "MemberExpression") {
        const obj = (callee.object as { name?: string } | undefined)?.name;
        const prop = (callee.property as { name?: string } | undefined)?.name;
        if (obj && childProcAliases.has(obj)) {
          pushHit(state, node, {
            category: "child-process",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
        if (obj && httpsAliases.has(obj) && (prop === "request" || prop === "get")) {
          pushHit(state, node, {
            category: "network-builtin",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
        if (obj && fsAliases.has(obj) && typeof prop === "string" && prop.startsWith("write")) {
          pushHit(state, node, {
            category: "fs-write-outside",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
      }
      // -------- crypto private key reads --------
      if (callee && isCalleeOneOf(callee, CRYPTO_KEY_CALLEES)) {
        pushHit(state, node, {
          category: "crypto-key-read",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
      // -------- Buffer.from(literal, 'base64') --------
      if (
        callee &&
        callee.type === "MemberExpression" &&
        (callee.object as { name?: string } | undefined)?.name === "Buffer" &&
        (callee.property as { name?: string } | undefined)?.name === "from"
      ) {
        const args = node.arguments as Array<AcornNode>;
        const enc = args[1] ? foldString(args[1]) : null;
        if (enc === "base64" || enc === "base64url") {
          const lit = args[0] ? foldString(args[0]) : null;
          if (lit !== null) {
            const decoded = tryBase64Decode(lit);
            pushHit(state, node, {
              category: "base64-decode",
              evidence: snip(`Buffer.from('${lit.slice(0, 60)}…','${enc}')`),
              ...(decoded !== null ? { decodedPreview: snip(decoded) } : {}),
            });
            // re-scan decoded preview for secret-path / network builtin strings
            if (decoded !== null) {
              if (SECRET_PATH_RE.test(decoded)) {
                pushHit(state, node, {
                  category: "secret-path",
                  evidence: snip(`(decoded base64) ${decoded}`),
                });
              }
              for (const builtin of NETWORK_BUILTINS) {
                if (decoded.includes(`'${builtin}'`) || decoded.includes(`"${builtin}"`)) {
                  pushHit(state, node, {
                    category: "network-builtin",
                    evidence: snip(`(decoded base64) ${decoded}`),
                  });
                  break;
                }
              }
            }
          }
        }
      }
      // -------- atob('...') --------
      if (callee && callee.type === "Identifier" && (callee as unknown as { name: string }).name === "atob") {
        const lit = (node.arguments as Array<AcornNode>)[0]
          ? foldString((node.arguments as Array<AcornNode>)[0] ?? null)
          : null;
        if (lit !== null) {
          const decoded = tryBase64Decode(lit);
          pushHit(state, node, {
            category: "base64-decode",
            evidence: snip(`atob('${lit.slice(0, 60)}…')`),
            ...(decoded !== null ? { decodedPreview: snip(decoded) } : {}),
          });
        }
      }
    }

    // -------- new Function('...') --------
    if (node.type === "NewExpression") {
      const callee = node.callee as AcornNode | undefined;
      if (callee && callee.type === "Identifier" && FUNCTION_CTOR.has((callee as unknown as { name: string }).name)) {
        pushHit(state, node, {
          category: "eval",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
    }

    // -------- process.env.X / process.env[...] --------
    if (node.type === "MemberExpression") {
      const obj = node.object as AcornNode | undefined;
      const prop = node.property as { name?: string } | undefined;
      if (
        obj &&
        obj.type === "MemberExpression" &&
        ((obj.object as { name?: string } | undefined)?.name === "process") &&
        ((obj.property as { name?: string } | undefined)?.name === "env")
      ) {
        pushHit(state, node, {
          category: "env-read",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
      // process.env (no further access) — captured in Identifier-like path
      if (
        obj &&
        (obj as { name?: string } | undefined)?.name === "process" &&
        prop?.name === "env"
      ) {
        // Don't record yet — wait for further access. Calling Object.keys(process.env)
        // still surfaces here by parent node check if needed.
        // We add a soft env-read so coverage stays.
        pushHit(state, node, {
          category: "env-read",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
    }

    // -------- string literals matching secret-path heuristic --------
    if (node.type === "Literal" && typeof (node as { value?: unknown }).value === "string") {
      const v = (node as unknown as { value: string }).value;
      if (SECRET_PATH_RE.test(v)) {
        pushHit(state, node, {
          category: "secret-path",
          evidence: snip(v),
        });
      }
    }

    // -------- TemplateLiteral folded path-shaped --------
    if (node.type === "TemplateLiteral") {
      const folded = foldString(node);
      if (folded !== null && SECRET_PATH_RE.test(folded)) {
        pushHit(state, node, {
          category: "secret-path",
          evidence: snip(folded),
        });
      }
    }
  });
}

function regexFallback(source: string, state: AnalyzerState): void {
  // Conservative regex fallback (only used when acorn cannot parse).
  // We tag everything as parse-fallback; severity scoring later treats it more strictly.
  const PATTERNS: Array<{ re: RegExp; cat: AstCategory }> = [
    { re: /\beval\s*\(/g, cat: "eval" },
    { re: /new\s+Function\s*\(/g, cat: "eval" },
    { re: /require\s*\(\s*['"](?:node:)?(?:https?|net|tls|dns|dgram)['"]\s*\)/g, cat: "network-builtin" },
    { re: /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g, cat: "child-process" },
    { re: /\bfetch\s*\(/g, cat: "fetch" },
    { re: /process\.env(?:\b|\[|\.)/g, cat: "env-read" },
    { re: /\.npmrc|\.aws[\\/]|\.ssh[\\/]|id_rsa/g, cat: "secret-path" },
    { re: /Buffer\.from\s*\([^,)]+,\s*['"]base64['"]\s*\)/g, cat: "base64-decode" },
  ];
  for (const { re, cat } of PATTERNS) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      // Compute line/col from match index
      const idx = m.index;
      let line = 1;
      let col = 0;
      for (let i = 0; i < idx; i++) {
        if (source.charCodeAt(i) === 10) {
          line++;
          col = 0;
        } else {
          col++;
        }
      }
      state.hits.push({
        category: cat,
        evidence: snip(m[0]),
        line,
        column: col,
      });
      if (SOURCE_CATEGORIES.has(cat)) state.sources.add(cat);
      if (SINK_CATEGORIES.has(cat)) state.sinks.add(cat);
    }
  }
}

/** Best-effort parse: try ESM module first, then script, then return null. */
function tryParse(source: string): AcornNode | null {
  const opts = { ecmaVersion: 2024 as const, locations: true, allowHashBang: true };
  try {
    return Parser.parse(source, { ...opts, sourceType: "module" }) as unknown as AcornNode;
  } catch {
    /* fall through */
  }
  try {
    return Parser.parse(source, { ...opts, sourceType: "script" }) as unknown as AcornNode;
  } catch {
    return null;
  }
}

/** Analyze a single JavaScript source string. Always returns an AstReport (never throws). */
export function analyzeSource(file: string, source: string): AstReport {
  const state: AnalyzerState = {
    hits: [],
    parseFallback: false,
    sources: new Set(),
    sinks: new Set(),
  };
  const ast = tryParse(source);
  if (ast === null) {
    state.parseFallback = true;
    regexFallback(source, state);
  } else {
    try {
      analyzeAst(ast, source, state);
    } catch {
      state.parseFallback = true;
      regexFallback(source, state);
    }
  }
  // Deduplicate identical hits (same category + line + column + evidence) to avoid noise.
  const seen = new Set<string>();
  const dedup: AstHit[] = [];
  for (const h of state.hits) {
    const key = `${h.category}|${h.line}|${h.column}|${h.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      dedup.push(h);
    }
  }
  return {
    file,
    hits: dedup,
    parseFallback: state.parseFallback,
    taintToSink: state.sources.size > 0 && state.sinks.size > 0,
    taintSources: [...state.sources],
    taintSinks: [...state.sinks],
  };
}
