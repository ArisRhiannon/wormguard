// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aris Rhiannon
//
// AST analyzer for JavaScript sources invoked from package lifecycle scripts.
// Two-pass design:
//
//   Pass 1 (collectAliases):
//     Walk every VariableDeclarator and parameter pattern; populate a unified
//     alias table that records which local identifiers resolve to dangerous
//     globals or builtins:
//
//        evalLike      -> eval, Function, vm.runIn*, ({}).constructor.constructor
//        requireLike   -> require, globalThis.require, module.constructor._load
//        fetchLike     -> fetch, globalThis.fetch
//        childProcLike -> require('child_process')
//        netBuiltinLike -> require('http' | 'https' | 'net' | 'tls' | 'dns' | 'dgram')
//        fsLike        -> require('fs')
//
//     Pass 1 also handles destructured property aliases:
//        const { exec } = require('child_process')
//        const { exec: e } = require('child_process')
//
//   Pass 2 (detectSinks):
//     Walk every CallExpression / NewExpression / MemberExpression / Literal
//     and decide whether it constitutes a finding, consulting the alias table
//     populated in Pass 1.
//
// Every red-team H1..H18 bypass is closed in Pass 2 by checking against the
// alias table rather than against literal identifier names. New detections:
//
//   * `(0, eval)(...)`           SequenceExpression with eval-alias tail
//   * `Reflect.apply(eval, ...)` Reflect-based eval
//   * `eval.call(...)`           call/apply/bind on eval-alias
//   * `import('...')`            dynamic ESM import, with constant folding
//   * `({}.constructor.constructor)('return process')()`  Function ctor via proto
//   * `process.binding(...)`     internal Node API
//   * `process.dlopen(...)`      load native shared object
//   * `module.constructor._load`  (= require)
//   * `new Worker(src, {eval:true})`  worker_threads with eval flag
//   * `globalThis.X` source for any of the above

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
const FS_BUILTINS = new Set(["fs", "node:fs", "fs/promises", "node:fs/promises"]);
const VM_BUILTINS = new Set(["vm", "node:vm"]);
const WORKER_BUILTINS = new Set(["worker_threads", "node:worker_threads"]);

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
  // M5 (red-team): strip NUL and ASCII control chars (other than \n,\r,\t)
  // from evidence strings. Some package.json files in the wild carry NULs
  // in scripts; passing those through unsanitized produces broken JSON
  // consumers and confusing terminal output.
  let cleaned = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) {
      cleaned += "\\0";
    } else if (c < 32 && c !== 9 && c !== 10 && c !== 13) {
      cleaned += `\\x${c.toString(16).padStart(2, "0")}`;
    } else {
      cleaned += s[i];
    }
  }
  return cleaned.length > MAX_EVIDENCE ? `${cleaned.slice(0, MAX_EVIDENCE - 1)}…` : cleaned;
}

// ---------------------------------------------------------------------------
// Constant folding (strings only)
// ---------------------------------------------------------------------------

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
      out += q && q.value && typeof q.value.cooked === "string" ? q.value.cooked : "";
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
  // String.fromCharCode(N, N, N, ...) — fold numeric Literal args.
  if (
    node.type === "CallExpression" &&
    (node.callee as AcornNode | undefined)?.type === "MemberExpression" &&
    (((node.callee as AcornNode).object as { name?: string } | undefined)?.name === "String") &&
    (((node.callee as AcornNode).property as { name?: string } | undefined)?.name === "fromCharCode")
  ) {
    const args = node.arguments as Array<AcornNode>;
    const codes: number[] = [];
    for (const a of args) {
      if (a.type === "Literal" && typeof (a as { value?: unknown }).value === "number") {
        codes.push((a as unknown as { value: number }).value);
      } else {
        return null;
      }
    }
    return String.fromCharCode(...codes);
  }
  return null;
}

function tryBase64Decode(literal: string): string | null {
  if (literal.length < 8) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(literal)) return null;
  try {
    const norm = literal.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(norm, "base64");
    if (buf.length === 0) return null;
    const decoded = buf.toString("utf8");
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

// ---------------------------------------------------------------------------
// Member-path canonicalization
// ---------------------------------------------------------------------------

function memberPath(node: AcornNode | undefined | null): string | null {
  if (!node) return null;
  if (node.type === "Identifier") return (node as unknown as { name: string }).name;
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression") {
    const obj = memberPath(node.object as AcornNode);
    let prop: string | null = null;
    if (!node.computed) {
      prop = (node.property as { name?: string } | undefined)?.name ?? null;
    } else {
      // Computed: try to fold the key as a string.
      prop = foldString(node.property as AcornNode);
    }
    if (obj === null || prop === null) return null;
    return `${obj}.${prop}`;
  }
  if (node.type === "ParenthesizedExpression") {
    return memberPath((node as { expression?: AcornNode }).expression ?? null);
  }
  // SequenceExpression — return path of last expression. (0, eval) -> "eval"
  if (node.type === "SequenceExpression") {
    const exprs = node.expressions as Array<AcornNode>;
    if (exprs.length === 0) return null;
    return memberPath(exprs[exprs.length - 1] ?? null);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Alias table — populated in Pass 1, consulted in Pass 2
// ---------------------------------------------------------------------------

interface AliasTable {
  /** identifiers whose call site is treated as eval / Function ctor / vm.runIn* */
  evalLike: Set<string>;
  /** identifiers whose call site is treated as require() */
  requireLike: Set<string>;
  /** identifiers whose call site is treated as fetch() */
  fetchLike: Set<string>;
  /** identifiers that hold a network-builtin module (http/https/net/tls/dns/dgram) */
  netBuiltinLike: Set<string>;
  /** identifiers that hold the child_process module */
  childProcLike: Set<string>;
  /** identifiers that hold the fs module */
  fsLike: Set<string>;
  /** identifiers destructured from child_process (exec, spawn, etc.) */
  childProcMethodLike: Set<string>;
  /** identifiers destructured from fs (writeFileSync, etc.) */
  fsWriteLike: Set<string>;
  /** identifiers that hold a Worker constructor */
  workerCtorLike: Set<string>;
}

function emptyAliases(): AliasTable {
  return {
    evalLike: new Set(["eval", "Function"]),
    requireLike: new Set(["require"]),
    fetchLike: new Set(["fetch"]),
    netBuiltinLike: new Set(),
    childProcLike: new Set(),
    fsLike: new Set(),
    childProcMethodLike: new Set([
      "exec",
      "execSync",
      "spawn",
      "spawnSync",
      "fork",
      "execFile",
      "execFileSync",
    ]),
    fsWriteLike: new Set(),
    workerCtorLike: new Set(),
  };
}

/** Classify an init expression for alias propagation. Returns the category(s)
 *  this expression resolves to, or null if it's not interesting. */
function classifyInit(node: AcornNode | undefined, aliases: AliasTable): {
  evalLike?: boolean;
  requireLike?: boolean;
  fetchLike?: boolean;
  netBuiltinLike?: boolean;
  childProcLike?: boolean;
  fsLike?: boolean;
  workerCtorLike?: boolean;
  fnCtorLike?: boolean;
  /** if this is a call to require(), the resolved literal name (when foldable) */
  requireResolved?: string | null;
} | null {
  if (!node) return null;

  // Identifier: `eval`, `require`, `fetch`, or any existing alias.
  if (node.type === "Identifier") {
    const name = (node as unknown as { name: string }).name;
    return {
      evalLike: aliases.evalLike.has(name),
      requireLike: aliases.requireLike.has(name),
      fetchLike: aliases.fetchLike.has(name),
      childProcLike: aliases.childProcLike.has(name),
      netBuiltinLike: aliases.netBuiltinLike.has(name),
      fsLike: aliases.fsLike.has(name),
      workerCtorLike: aliases.workerCtorLike.has(name),
    };
  }

  // MemberExpression: globalThis.eval, globalThis.require, globalThis.fetch,
  // module.constructor._load, ({}).constructor.constructor, etc.
  if (node.type === "MemberExpression" || node.type === "SequenceExpression") {
    const path = memberPath(node);
    if (!path) return null;
    if (path === "globalThis.eval" || path === "global.eval") return { evalLike: true };
    if (path === "globalThis.Function" || path === "global.Function") return { evalLike: true };
    if (path === "globalThis.require" || path === "global.require" || path === "module.require") {
      return { requireLike: true };
    }
    if (path === "module.constructor._load") return { requireLike: true };
    if (path === "globalThis.fetch" || path === "global.fetch") return { fetchLike: true };
    return null;
  }

  // Function constructor via prototype chain:
  //   ({}).constructor.constructor
  //   [].constructor.constructor
  //   "".constructor.constructor
  //   (async function(){}).constructor
  if (node.type === "MemberExpression") {
    /* handled above */
  }
  // Detect the Function ctor pattern on any expression.x.constructor.constructor or .constructor for async fn.
  if (node.type === "MemberExpression") {
    /* unreachable, kept for clarity */
  }

  // CallExpression: require('...'), `<requireAlias>('...')`.
  if (node.type === "CallExpression") {
    const callee = node.callee as AcornNode | undefined;
    const calleeName = callee && callee.type === "Identifier" ? (callee as unknown as { name: string }).name : null;
    const calleePath = callee ? memberPath(callee) : null;
    const isRequire =
      (calleeName !== null && aliases.requireLike.has(calleeName)) ||
      calleePath === "module.constructor._load" ||
      calleePath === "globalThis.require" ||
      calleePath === "global.require";
    if (isRequire) {
      const args = node.arguments as Array<AcornNode>;
      const folded = args[0] ? foldString(args[0]) : null;
      if (folded === null) return { requireResolved: null };
      if (NETWORK_BUILTINS.has(folded)) return { netBuiltinLike: true, requireResolved: folded };
      if (CHILD_PROC_BUILTINS.has(folded)) return { childProcLike: true, requireResolved: folded };
      if (FS_BUILTINS.has(folded)) return { fsLike: true, requireResolved: folded };
      if (VM_BUILTINS.has(folded)) return { evalLike: true, requireResolved: folded };
      if (WORKER_BUILTINS.has(folded)) return { workerCtorLike: false, requireResolved: folded };
      return { requireResolved: folded };
    }
  }

  return null;
}

// Detect Function-ctor-via-proto chain at any node position.
// The pattern is a MemberExpression whose `.property === 'constructor'`
// resolved twice (or wrapped via constructor on a literal).
function isFnCtorViaProto(node: AcornNode | undefined): boolean {
  if (!node) return false;
  // Any chain of MemberExpression ending in two consecutive `.constructor`
  // accesses qualifies. e.g. ({}).constructor.constructor
  let depth = 0;
  let cur: AcornNode | null = node;
  while (cur && cur.type === "MemberExpression" && !cur.computed) {
    const propName = (cur.property as { name?: string } | undefined)?.name;
    if (propName === "constructor") depth++;
    else break;
    cur = cur.object as AcornNode;
  }
  return depth >= 2;
}

// ---------------------------------------------------------------------------
// Hits / state plumbing
// ---------------------------------------------------------------------------

interface AnalyzerState {
  hits: AstHit[];
  parseFallback: boolean;
  sources: Set<AstCategory>;
  sinks: Set<AstCategory>;
  aliases: AliasTable;
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

// ---------------------------------------------------------------------------
// Pass 1 — collect aliases
// ---------------------------------------------------------------------------

function collectAliases(ast: AcornNode, state: AnalyzerState): void {
  walk.fullAncestor(ast as Node, (rawNode) => {
    const node = rawNode as AcornNode;
    if (node.type !== "VariableDeclarator") return;
    const init = node.init as AcornNode | undefined;
    if (!init) return;

    // Function-ctor-via-proto:  const F = ({}).constructor.constructor
    // Also captures: const F = [].constructor.constructor
    if (isFnCtorViaProto(init)) {
      const id = node.id as AcornNode;
      if (id.type === "Identifier") state.aliases.evalLike.add((id as unknown as { name: string }).name);
      return;
    }

    const cls = classifyInit(init, state.aliases);
    if (!cls) return;

    const id = node.id as AcornNode;

    // Simple identifier binding: const X = <init>
    if (id.type === "Identifier") {
      const name = (id as unknown as { name: string }).name;
      if (cls.evalLike) state.aliases.evalLike.add(name);
      if (cls.requireLike) state.aliases.requireLike.add(name);
      if (cls.fetchLike) state.aliases.fetchLike.add(name);
      if (cls.netBuiltinLike) state.aliases.netBuiltinLike.add(name);
      if (cls.childProcLike) state.aliases.childProcLike.add(name);
      if (cls.fsLike) state.aliases.fsLike.add(name);
      if (cls.workerCtorLike) state.aliases.workerCtorLike.add(name);
      return;
    }

    // Object pattern: const { exec, spawn: s } = require('child_process')
    if (id.type === "ObjectPattern" && cls.childProcLike) {
      const props = id.properties as Array<AcornNode>;
      for (const prop of props) {
        const value = (prop as { value?: AcornNode }).value;
        if (value && value.type === "Identifier") {
          state.aliases.childProcMethodLike.add((value as unknown as { name: string }).name);
        }
      }
    }
    if (id.type === "ObjectPattern" && cls.fsLike) {
      const props = id.properties as Array<AcornNode>;
      for (const prop of props) {
        const value = (prop as { value?: AcornNode }).value;
        if (value && value.type === "Identifier") {
          const name = (value as unknown as { name: string }).name;
          if (name.startsWith("write")) state.aliases.fsWriteLike.add(name);
        }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Pass 2 — detect sinks
// ---------------------------------------------------------------------------

function detectSinks(ast: AcornNode, source: string, state: AnalyzerState): void {
  const a = state.aliases;

  walk.fullAncestor(ast as Node, (rawNode) => {
    const node = rawNode as AcornNode;

    // ---- CallExpression dispatch ----
    if (node.type === "CallExpression") {
      const callee = node.callee as AcornNode | undefined;
      const calleeName = callee && callee.type === "Identifier"
        ? (callee as unknown as { name: string }).name
        : null;
      const calleePath = callee ? memberPath(callee) : null;
      const args = node.arguments as Array<AcornNode>;
      const evidence = snip(source.slice(node.start as number, node.end as number));

      // Direct eval-alias call:  eval("..."), F("..."), evilAlias("...")
      if (calleeName && a.evalLike.has(calleeName)) {
        pushHit(state, node, { category: "eval", evidence });
        const arg0 = args[0];
        if (arg0 && foldString(arg0) === null) {
          pushHit(state, node, { category: "string-concat-eval", evidence });
        }
      }

      // Require-alias call:  require('https'), r('https')
      if (calleeName && a.requireLike.has(calleeName)) {
        const folded = args[0] ? foldString(args[0]) : null;
        if (folded === null) {
          if (args[0]) pushHit(state, node, { category: "dynamic-require", evidence });
        } else {
          if (NETWORK_BUILTINS.has(folded)) {
            pushHit(state, node, {
              category: "network-builtin",
              evidence: snip(`require('${folded}')`),
              resolvedLiteral: folded,
            });
          }
          if (CHILD_PROC_BUILTINS.has(folded)) {
            pushHit(state, node, {
              category: "child-process",
              evidence: snip(`require('${folded}')`),
              resolvedLiteral: folded,
            });
          }
          if (VM_BUILTINS.has(folded)) {
            pushHit(state, node, {
              category: "eval",
              evidence: snip(`require('${folded}')  // vm`),
              resolvedLiteral: folded,
            });
          }
        }
      }

      // module.constructor._load / globalThis.require — covered by aliasing
      // when the result is assigned, but ALSO catch direct calls inline.
      if (calleePath === "module.constructor._load" || calleePath === "globalThis.require" || calleePath === "global.require") {
        const folded = args[0] ? foldString(args[0]) : null;
        if (folded !== null) {
          if (NETWORK_BUILTINS.has(folded)) {
            pushHit(state, node, { category: "network-builtin", evidence, resolvedLiteral: folded });
          }
          if (CHILD_PROC_BUILTINS.has(folded)) {
            pushHit(state, node, { category: "child-process", evidence, resolvedLiteral: folded });
          }
        } else {
          pushHit(state, node, { category: "dynamic-require", evidence });
        }
      }

      // globalThis.eval(...) / global.eval(...) — direct invocation.
      if (calleePath === "globalThis.eval" || calleePath === "global.eval") {
        pushHit(state, node, { category: "eval", evidence });
        const arg0 = args[0];
        if (arg0 && foldString(arg0) === null) {
          pushHit(state, node, { category: "string-concat-eval", evidence });
        }
      }
      if (calleePath === "globalThis.Function" || calleePath === "global.Function") {
        pushHit(state, node, { category: "eval", evidence });
      }
      // globalThis.fetch(...) / globalThis.fetch.call/apply(...)
      if (calleePath === "globalThis.fetch" || calleePath === "global.fetch") {
        pushHit(state, node, { category: "fetch", evidence });
      }

      // Function-ctor-via-proto chain called directly:
      //   ({}.constructor.constructor)('return process')
      //   [].constructor.constructor('return process')()
      if (callee && isFnCtorViaProto(callee)) {
        pushHit(state, node, { category: "eval", evidence });
      }

      // Reflect.apply(eval, ...) / Reflect.apply(<evalAlias>, ...)
      if (calleePath === "Reflect.apply") {
        const target = args[0];
        const targetName = target && target.type === "Identifier"
          ? (target as unknown as { name: string }).name
          : null;
        if (targetName && a.evalLike.has(targetName)) {
          pushHit(state, node, { category: "eval", evidence });
        }
        if (targetName && a.requireLike.has(targetName)) {
          // Reflect.apply(require, null, ['https']) — string folding on args[2][0]
          const argsArr = args[2];
          if (argsArr && argsArr.type === "ArrayExpression") {
            const elems = (argsArr as { elements?: Array<AcornNode | null> }).elements ?? [];
            const folded = elems[0] ? foldString(elems[0]) : null;
            if (folded !== null && NETWORK_BUILTINS.has(folded)) {
              pushHit(state, node, { category: "network-builtin", evidence, resolvedLiteral: folded });
            }
          }
        }
      }

      // <evalAlias>.call/apply/bind(...) where the chain may be deeper than one MemberExpression.
      // Examples covered:
      //   eval.call(null, ...)            -> obj path = "eval"
      //   globalThis.eval.call(null, ...) -> obj path = "globalThis.eval"
      //   globalThis.fetch.call(null, ...) -> obj path = "globalThis.fetch"
      if (callee && callee.type === "MemberExpression" && !callee.computed) {
        const objPath = memberPath(callee.object as AcornNode);
        const prop = (callee.property as { name?: string } | undefined)?.name;
        const isCallOrApply = prop === "call" || prop === "apply" || prop === "bind";
        if (isCallOrApply && objPath !== null) {
          // Eval-likes
          if (
            objPath === "eval" ||
            objPath === "Function" ||
            objPath === "globalThis.eval" ||
            objPath === "global.eval" ||
            objPath === "globalThis.Function" ||
            objPath === "global.Function" ||
            a.evalLike.has(objPath)
          ) {
            pushHit(state, node, { category: "eval", evidence });
          }
          // Fetch-likes
          if (
            objPath === "fetch" ||
            objPath === "globalThis.fetch" ||
            objPath === "global.fetch" ||
            a.fetchLike.has(objPath)
          ) {
            pushHit(state, node, { category: "fetch", evidence });
          }
        }
      }

      // <evalAlias>.call/apply/bind(...) — single-identifier object form (existing path).
      if (callee && callee.type === "MemberExpression" && !callee.computed) {
        const obj = callee.object as AcornNode | undefined;
        const objName = obj && obj.type === "Identifier" ? (obj as unknown as { name: string }).name : null;
        const prop = (callee.property as { name?: string } | undefined)?.name;
        if (objName && a.evalLike.has(objName) && (prop === "call" || prop === "apply" || prop === "bind")) {
          pushHit(state, node, { category: "eval", evidence });
        }
        // <fetchAlias>.call/apply(...)
        if (objName && a.fetchLike.has(objName) && (prop === "call" || prop === "apply" || prop === "bind")) {
          pushHit(state, node, { category: "fetch", evidence });
        }
        // <netBuiltinAlias>.request/get(...)  — http(s).request, https.get
        if (objName && a.netBuiltinLike.has(objName) && (prop === "request" || prop === "get" || prop === "createConnection" || prop === "connect")) {
          pushHit(state, node, { category: "network-builtin", evidence });
        }
        // <childProcAlias>.exec/spawn/...
        if (
          objName &&
          a.childProcLike.has(objName) &&
          ["exec", "execSync", "spawn", "spawnSync", "fork", "execFile", "execFileSync"].includes(prop ?? "")
        ) {
          pushHit(state, node, { category: "child-process", evidence });
        }
        // <fsAlias>.writeFile/writeFileSync/appendFile/...
        if (objName && a.fsLike.has(objName) && typeof prop === "string" && prop.startsWith("write")) {
          pushHit(state, node, { category: "fs-write-outside", evidence });
        }
      }

      // M1 worm-propagation primitive (red-team): an install script that
      // writes to './package.json' (or any package.json path) AND invokes
      // `npm publish` (directly or via execSync) is the canonical
      // self-propagating worm pattern. We surface this with the
      // worm-propagate category so the orchestrator lifts it to critical.
      // We accept any callee that ends in writeFile/writeFileSync —
      // including the inline pattern `require('fs').writeFileSync(...)`
      // where the object is a call expression.
      const calleeNameForWormCheck = calleeName;
      const calleePropName =
        callee && callee.type === "MemberExpression" && !callee.computed
          ? (callee.property as { name?: string } | undefined)?.name ?? null
          : null;
      const isFsWriteCall =
        calleeNameForWormCheck === "writeFileSync" ||
        calleeNameForWormCheck === "writeFile" ||
        calleePropName === "writeFileSync" ||
        calleePropName === "writeFile";
      if (isFsWriteCall) {
        const arg0 = args[0];
        const folded = arg0 ? foldString(arg0) : null;
        if (folded !== null && /(?:^|[\\/])package\.json$/i.test(folded)) {
          pushHit(state, node, {
            category: "fs-write-outside",
            evidence: snip(`writeFile to ${folded}  // possible worm self-propagation`),
          });
          pushHit(state, node, { category: "worm-propagate", evidence: snip(`writeFile package.json`) });
        }
      }
      const isExecLike =
        calleeNameForWormCheck === "execSync" ||
        calleeNameForWormCheck === "exec" ||
        calleeNameForWormCheck === "spawnSync" ||
        calleeNameForWormCheck === "spawn" ||
        calleePropName === "execSync" ||
        calleePropName === "exec" ||
        calleePropName === "spawnSync" ||
        calleePropName === "spawn";
      if (isExecLike) {
        const arg0 = args[0];
        const folded0 = arg0 ? foldString(arg0) : null;
        const looksLikePublish =
          (folded0 !== null && /\bnpm\b[\s\S]{0,40}\bpublish\b/i.test(folded0)) ||
          (folded0 === "npm" &&
            (() => {
              const arg1 = args[1];
              if (!arg1 || arg1.type !== "ArrayExpression") return false;
              const elems = (arg1 as { elements?: Array<AcornNode | null> }).elements ?? [];
              return elems.some((el) => el && foldString(el) === "publish");
            })());
        if (looksLikePublish) {
          pushHit(state, node, {
            category: "child-process",
            evidence: snip(`spawn npm publish  // possible worm self-propagation`),
          });
          pushHit(state, node, { category: "worm-propagate", evidence: snip(`npm publish call`) });
        }
      }

      // Identifier child-process method aliases (destructured)
      if (calleeName && a.childProcMethodLike.has(calleeName) && calleeName !== "spawn") {
        pushHit(state, node, { category: "child-process", evidence });
      }
      // 'spawn' alone is a common identifier; only fire when destructured FROM child_process,
      // which we know if it was added via Pass 1. We added the destructured aliases there.
      if (calleeName === "spawn" && a.childProcMethodLike.has("spawn") && a.childProcLike.size > 0) {
        // Already in default set; this is fine to fire.
        pushHit(state, node, { category: "child-process", evidence });
      }

      // fetch-alias direct call
      if (calleeName && a.fetchLike.has(calleeName)) {
        pushHit(state, node, { category: "fetch", evidence });
      }

      // process.binding(...) / process.dlopen(...)
      if (calleePath === "process.binding") {
        pushHit(state, node, { category: "eval", evidence });
        pushHit(state, node, { category: "network-builtin", evidence: snip(`${evidence}  // process.binding internal API`) });
      }
      if (calleePath === "process.dlopen") {
        pushHit(state, node, { category: "child-process", evidence: snip(`${evidence}  // process.dlopen native module load`) });
      }

      // vm.runIn* via alias on vm module
      if (
        callee &&
        callee.type === "MemberExpression" &&
        !callee.computed &&
        memberPath(callee.object as AcornNode) &&
        ((callee.property as { name?: string } | undefined)?.name?.startsWith("runIn") ||
          (callee.property as { name?: string } | undefined)?.name === "compileFunction")
      ) {
        const objPath = memberPath(callee.object as AcornNode);
        if (objPath === "vm") {
          pushHit(state, node, { category: "eval", evidence });
        }
      }

      // Buffer.from(literal, 'base64')
      if (
        callee &&
        callee.type === "MemberExpression" &&
        (callee.object as { name?: string } | undefined)?.name === "Buffer" &&
        (callee.property as { name?: string } | undefined)?.name === "from"
      ) {
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
            if (decoded !== null) {
              if (SECRET_PATH_RE.test(decoded)) {
                pushHit(state, node, { category: "secret-path", evidence: snip(`(decoded base64) ${decoded}`) });
              }
              for (const builtin of NETWORK_BUILTINS) {
                if (decoded.includes(`'${builtin}'`) || decoded.includes(`"${builtin}"`)) {
                  pushHit(state, node, { category: "network-builtin", evidence: snip(`(decoded base64) ${decoded}`) });
                  break;
                }
              }
            }
          }
        }
      }

      // atob('literal')
      if (calleeName === "atob") {
        const lit = args[0] ? foldString(args[0]) : null;
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

    // ---- NewExpression: new Function('...'), new Worker(src, {eval:true}) ----
    if (node.type === "NewExpression") {
      const callee = node.callee as AcornNode | undefined;
      const calleeName = callee && callee.type === "Identifier"
        ? (callee as unknown as { name: string }).name
        : null;
      const evidence = snip(source.slice(node.start as number, node.end as number));

      if (calleeName && a.evalLike.has(calleeName)) {
        pushHit(state, node, { category: "eval", evidence });
      }

      // new Worker(src, {eval:true}) — direct or via alias.
      // Detect when callee resolves to a Worker constructor (alias or
      // member access on a worker_threads-bound module).
      const calleePath = callee ? memberPath(callee) : null;
      const isWorker = (() => {
        if (!callee) return false;
        if (callee.type === "Identifier" && a.workerCtorLike.has((callee as unknown as { name: string }).name)) {
          return true;
        }
        if (callee.type === "MemberExpression") {
          const obj = callee.object as AcornNode | undefined;
          const prop = (callee.property as { name?: string } | undefined)?.name;
          if (prop !== "Worker") return false;
          if (!obj) return false;
          // worker_threads is namespaced; check if obj is bound to worker_threads via require.
          // We accept Worker on any identifier path here and rely on the {eval:true} option as the
          // discriminator, since misclassifying is a low-cost signal.
          return true;
        }
        // new (require('worker_threads').Worker)(...)
        return calleePath === "require.Worker"; // not a real path; placeholder
      })();
      if (isWorker) {
        const args = node.arguments as Array<AcornNode>;
        const opts = args[1];
        if (opts && opts.type === "ObjectExpression") {
          const props = (opts as { properties?: Array<AcornNode> }).properties ?? [];
          for (const p of props) {
            const key = (p as { key?: AcornNode }).key;
            const value = (p as { value?: AcornNode }).value;
            const keyName =
              key && key.type === "Identifier"
                ? (key as unknown as { name: string }).name
                : key && key.type === "Literal"
                  ? String((key as unknown as { value: unknown }).value)
                  : null;
            const valBool =
              value && value.type === "Literal" ? Boolean((value as unknown as { value: unknown }).value) : false;
            if (keyName === "eval" && valBool) {
              pushHit(state, node, { category: "eval", evidence: snip(`${evidence}  // new Worker({eval:true})`) });
            }
          }
        }
        // The first arg to a Worker(eval:true) is treated as inline JS source — re-scan it.
        const arg0 = args[0];
        const folded = arg0 ? foldString(arg0) : null;
        if (folded !== null) {
          // Lightweight re-scan of the inner source for high-signal substrings.
          if (/require\s*\(\s*['"](?:node:)?(?:https?|net|tls|dns|dgram|child_process)['"]/i.test(folded)) {
            pushHit(state, node, {
              category: "network-builtin",
              evidence: snip(`Worker inline source: ${folded.slice(0, 120)}`),
            });
          }
        }
      }
    }

    // ---- (0, eval)(...) — SequenceExpression in callee position ----
    if (
      node.type === "CallExpression" &&
      (node.callee as AcornNode | undefined)?.type === "SequenceExpression"
    ) {
      const seqExprs = ((node.callee as AcornNode).expressions as Array<AcornNode>) ?? [];
      const last = seqExprs[seqExprs.length - 1];
      const lastName = last && last.type === "Identifier"
        ? (last as unknown as { name: string }).name
        : null;
      if (lastName && a.evalLike.has(lastName)) {
        pushHit(state, node, { category: "eval", evidence: snip(source.slice(node.start as number, node.end as number)) });
      }
      const lastPath = last ? memberPath(last) : null;
      if (lastPath === "globalThis.eval" || lastPath === "global.eval") {
        pushHit(state, node, { category: "eval", evidence: snip(source.slice(node.start as number, node.end as number)) });
      }
    }

    // ---- import('...') dynamic ESM import ----
    if (node.type === "ImportExpression") {
      const arg = (node as { source?: AcornNode }).source;
      const folded = arg ? foldString(arg) : null;
      const evidence = snip(source.slice(node.start as number, node.end as number));
      if (folded === null) {
        pushHit(state, node, { category: "dynamic-require", evidence });
      } else {
        if (NETWORK_BUILTINS.has(folded)) {
          pushHit(state, node, { category: "network-builtin", evidence: snip(`import('${folded}')`), resolvedLiteral: folded });
        }
        if (CHILD_PROC_BUILTINS.has(folded)) {
          pushHit(state, node, { category: "child-process", evidence: snip(`import('${folded}')`), resolvedLiteral: folded });
        }
      }
    }

    // ---- ImportDeclaration source ----
    if (node.type === "ImportDeclaration") {
      const src = (node.source as { value?: unknown } | undefined)?.value;
      if (typeof src === "string") {
        if (NETWORK_BUILTINS.has(src)) {
          pushHit(state, node, { category: "network-builtin", evidence: `import from '${src}'`, resolvedLiteral: src });
        }
        if (CHILD_PROC_BUILTINS.has(src)) {
          pushHit(state, node, { category: "child-process", evidence: `import from '${src}'`, resolvedLiteral: src });
        }
      }
    }

    // ---- process.env access ----
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
      if (
        obj &&
        (obj as { name?: string } | undefined)?.name === "process" &&
        prop?.name === "env"
      ) {
        pushHit(state, node, {
          category: "env-read",
          evidence: snip(source.slice(node.start as number, node.end as number)),
        });
      }
      // process[<computed>] where the computed value folds to "env"
      if (
        node.computed &&
        obj &&
        (obj as { name?: string } | undefined)?.name === "process"
      ) {
        const folded = foldString(node.property as AcornNode);
        if (folded === "env") {
          pushHit(state, node, {
            category: "env-read",
            evidence: snip(source.slice(node.start as number, node.end as number)),
          });
        }
      }
    }

    // ---- secret-path string literals + template literals ----
    if (node.type === "Literal" && typeof (node as { value?: unknown }).value === "string") {
      const v = (node as unknown as { value: string }).value;
      if (SECRET_PATH_RE.test(v)) {
        pushHit(state, node, { category: "secret-path", evidence: snip(v) });
      }
    }
    if (node.type === "TemplateLiteral") {
      const folded = foldString(node);
      if (folded !== null && SECRET_PATH_RE.test(folded)) {
        pushHit(state, node, { category: "secret-path", evidence: snip(folded) });
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Regex fallback (only used when acorn cannot parse)
// ---------------------------------------------------------------------------

function regexFallback(source: string, state: AnalyzerState): void {
  const PATTERNS: Array<{ re: RegExp; cat: AstCategory }> = [
    { re: /\beval\s*\(/g, cat: "eval" },
    { re: /new\s+Function\s*\(/g, cat: "eval" },
    { re: /\(\s*0\s*,\s*eval\s*\)/g, cat: "eval" },
    { re: /Reflect\.apply\s*\(\s*eval\b/g, cat: "eval" },
    { re: /\bimport\s*\(\s*['"`](?:node:)?(?:https?|net|tls|dns|dgram)['"`]/g, cat: "network-builtin" },
    { re: /require\s*\(\s*['"](?:node:)?(?:https?|net|tls|dns|dgram)['"]\s*\)/g, cat: "network-builtin" },
    { re: /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g, cat: "child-process" },
    { re: /module\.constructor\._load\s*\(/g, cat: "child-process" },
    { re: /process\.(?:binding|dlopen)\s*\(/g, cat: "child-process" },
    { re: /\bfetch\s*\(/g, cat: "fetch" },
    { re: /process\.env(?:\b|\[|\.)/g, cat: "env-read" },
    { re: /\.npmrc|\.aws[\\/]|\.ssh[\\/]|id_rsa/g, cat: "secret-path" },
    { re: /Buffer\.from\s*\([^,)]+,\s*['"]base64['"]\s*\)/g, cat: "base64-decode" },
  ];
  for (const { re, cat } of PATTERNS) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
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
      state.hits.push({ category: cat, evidence: snip(m[0]), line, column: col });
      if (SOURCE_CATEGORIES.has(cat)) state.sources.add(cat);
      if (SINK_CATEGORIES.has(cat)) state.sinks.add(cat);
    }
  }
}

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

/** Analyze a single JavaScript source string. Always returns an AstReport. */
export function analyzeSource(file: string, source: string): AstReport {
  const state: AnalyzerState = {
    hits: [],
    parseFallback: false,
    sources: new Set(),
    sinks: new Set(),
    aliases: emptyAliases(),
  };
  const ast = tryParse(source);
  if (ast === null) {
    state.parseFallback = true;
    regexFallback(source, state);
  } else {
    try {
      collectAliases(ast, state);
      detectSinks(ast, source, state);
    } catch {
      state.parseFallback = true;
      regexFallback(source, state);
    }
  }
  // Deduplicate identical hits.
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
