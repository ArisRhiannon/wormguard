// SPDX-License-Identifier: MIT
import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
    "corpus/index": "src/corpus/index.ts",
  },
  outDir: "dist",
  format: ["esm"],
  target: "node20",
  platform: "node",
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  shims: false,
  // Bundle our own source; keep runtime deps external so npm install
  // resolves them normally. (We list every runtime dep here for clarity.)
  external: [
    "acorn",
    "acorn-walk",
    "shell-quote",
    "ssri",
    "yaml",
    "@yarnpkg/lockfile",
    "sigstore",
    "semver",
  ],
  // CLI entry needs a shebang so it's executable when symlinked into bin/.
  // We strip the source shebang (#!/usr/bin/env bun, used during dev) and
  // inject node so the published package runs on any Node 20+ install.
  esbuildOptions(options) {
    options.legalComments = "none";
  },
  banner(ctx) {
    if (ctx.format === "esm") {
      return { js: "" };
    }
    return {};
  },
  // tsup runs an onSuccess hook after each successful build; use it to
  // prepend the node shebang to dist/cli.js and chmod +x.
  async onSuccess() {
    const { readFileSync, writeFileSync, chmodSync } = await import("node:fs");
    const cliPath = "dist/cli.js";
    const original = readFileSync(cliPath, "utf8");
    // Strip any preserved source shebang (#!/usr/bin/env bun).
    const stripped = original.replace(/^#![^\n]*\n/, "");
    writeFileSync(cliPath, `#!/usr/bin/env node\n${stripped}`);
    chmodSync(cliPath, 0o755);
  },
});
