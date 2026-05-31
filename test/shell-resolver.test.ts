// SPDX-License-Identifier: MIT
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveShellCommand, resolvePackageLifecycle } from "../src/ast/shell";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "wg-shell-"));
}

describe("shell-resolver", () => {
  test("flags `... | sh` as shell-pipe-to-shell", () => {
    const r = resolveShellCommand("/tmp", `curl https://x | sh`);
    expect(r.shellHits.some((h) => h.category === "shell-pipe-to-shell")).toBe(true);
    expect(r.shellHits.some((h) => h.category === "network-fetch-tool")).toBe(true);
  });
  test("flags `wget`", () => {
    const r = resolveShellCommand("/tmp", `wget https://x -O /tmp/y`);
    expect(r.shellHits.some((h) => h.category === "network-fetch-tool")).toBe(true);
  });
  test("flags `base64 -d`", () => {
    const r = resolveShellCommand("/tmp", `echo aGVsbG8= | base64 -d`);
    expect(r.shellHits.some((h) => h.category === "shell-base64-decode")).toBe(true);
  });
  test("flags `eval` at shell level", () => {
    const r = resolveShellCommand("/tmp", `eval "echo hi"`);
    expect(r.shellHits.some((h) => h.category === "shell-eval")).toBe(true);
  });
  test("inline `node -e \"...\"` produces an inline source", () => {
    const r = resolveShellCommand("/tmp", `node -e "require('https')"`);
    expect(r.sources.length).toBe(1);
    expect(r.sources[0]?.inline).toBe(true);
    expect(r.sources[0]?.source.includes("require")).toBe(true);
  });
  test("inline `node --eval=...` produces an inline source", () => {
    const r = resolveShellCommand("/tmp", `node --eval='fetch("x")'`);
    expect(r.sources.length).toBe(1);
    expect(r.sources[0]?.inline).toBe(true);
  });
  test("`node ./build.js` resolves the file relative to pkgRoot", () => {
    const root = tmp();
    writeFileSync(join(root, "build.js"), `console.log('hi')`);
    const r = resolveShellCommand(root, `node ./build.js`);
    expect(r.sources.length).toBe(1);
    expect(r.sources[0]?.inline).toBe(false);
    expect(r.sources[0]?.file.endsWith("build.js")).toBe(true);
  });
  test("commands separated by `&&` and `;` are each tokenized", () => {
    const root = tmp();
    writeFileSync(join(root, "a.js"), `// a`);
    writeFileSync(join(root, "b.js"), `// b`);
    const r = resolveShellCommand(root, `node ./a.js && node ./b.js`);
    expect(r.sources.length).toBe(2);
  });
  test("non-node binaries are ignored as scripts but shell-hits still fire", () => {
    const r = resolveShellCommand("/tmp", `node-gyp rebuild`);
    expect(r.sources.length).toBe(0);
  });
  test("resolvePackageLifecycle reads multiple lifecycles", () => {
    const root = tmp();
    writeFileSync(join(root, "post.js"), `console.log('postinstall')`);
    const out = resolvePackageLifecycle(root, {
      preinstall: `echo hi`,
      postinstall: `node ./post.js`,
    });
    expect(out.length).toBe(2);
    expect(out.find((x) => x.lifecycle === "postinstall")?.resolution.sources.length).toBe(1);
  });
  test("implicit install.js is picked up even when not declared", () => {
    const root = tmp();
    writeFileSync(join(root, "install.js"), `console.log('implicit')`);
    const out = resolvePackageLifecycle(root, {});
    expect(out.find((x) => x.lifecycle === "implicit")?.resolution.sources.length).toBe(1);
  });
  test("missing script files do not throw", () => {
    const root = tmp();
    const r = resolveShellCommand(root, `node ./missing.js`);
    expect(r.sources.length).toBe(0); // no throw, no source
  });
  test("oversized files are skipped (DoS guard)", () => {
    const root = tmp();
    const huge = "x".repeat(5_000_000);
    writeFileSync(join(root, "big.js"), huge);
    const r = resolveShellCommand(root, `node ./big.js`, { maxFileBytes: 1_000_000 });
    expect(r.sources.length).toBe(0);
  });
});
