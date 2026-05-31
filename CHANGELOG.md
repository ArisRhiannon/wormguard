# Changelog

All notable changes to wormguard are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and this project
follows [Semantic Versioning](https://semver.org/).

## [1.0.0-rc.1] — 2026-05-31

This release is a near-total rewrite of v0 in response to a hard external
review. Each major change addresses a specific, named critique.

### Added

- **AST-grade analyzer** (`src/ast/analyzer.ts`): real JavaScript parsing
  with `acorn`, walking with `acorn-walk`. Detects `eval`, `new Function`,
  `vm.runIn*`, dynamic `require()`/`import()`, network builtins via alias
  tracking (`const cp = require('child_process')`), `fetch()`,
  `process.env`, secret-path string literals, `crypto.createPrivateKey`,
  `Buffer.from(literal,'base64')` (with decoded re-scan), `atob(literal)`.
  Anti-evasion: constant folding for `+` and template literals so
  `require('ht'+'tps')` is detected. Regex fallback for unparseable
  sources (and the parse-failure itself is a finding).
- **Source-to-sink taint approximation**: `env-read`/`secret-path`/
  `crypto-key-read` reaching `network-builtin`/`fetch`/`child-process`/
  `shell-pipe` escalates the AST hit's severity one rung. This is the
  difference between "package reads `process.env`" (low) and "package
  reads `process.env.NPM_TOKEN` and sends it to a fetch()" (critical).
- **Multi-package-manager lockfile parsers** (`src/pm/`): npm v1/v2/v3
  (existing), pnpm v6/v7/v9 (with the v9 `packages` + `snapshots`
  metadata merge), yarn classic via `@yarnpkg/lockfile`, yarn berry via
  the `yaml` parser, bun.lock JSONC. Auto-detection in priority order
  pnpm > yarn-berry > yarn-classic > npm > bun.
- **Offline IoC corpus** (`data/iocs.json`): 23 055 confirmed-malicious
  npm package names from the public GitHub Advisory Database
  `type=malware` feed, plus 7 well-attested C2/exfil hostnames.
  Refreshable via `bun run refresh-corpus` (the only network-touching
  code path; the audit pipeline itself runs entirely offline).
- **Script-fingerprint allowlist** (`data/script-allowlist.json`):
  sha256 hashes of the lifecycle-script body strings of 28 widely-used
  native packages (esbuild, sharp, prisma, bcrypt, husky, electron,
  playwright, …) across all non-deprecated versions, with an
  `origins` audit trail showing the actual body text behind each hash.
  Populated from the npm registry packument via
  `scripts/populate-allowlist.ts`.
- **Worm-injection signature detection** (`WG-SCRIPT-FINGERPRINT-DRIFT`):
  a package in the curated allowlist whose lifecycle-script body hash
  does **not** match any accepted fingerprint emits a *critical*
  finding. This is the "trusted package, modified install script"
  pattern.
- **Sigstore provenance support** (`src/provenance/verify.ts`):
  reads npm v9+ `signatures` and `dist.attestations` from the
  lockfile; provides `verifyBundle()` that delegates to `sigstore-js`
  for offline cryptographic verification of supplied bundles. Missing
  provenance is a low advisory; verification failure is critical.
- **Granular config schema** (`scriptAllowlist[]` with optional
  `scriptSha256` binding, `scriptFingerprints` for user fingerprint
  extensions). The legacy `allowInstallScripts: string[]` whole-package
  switch is parsed for backward compatibility but is documented as
  deprecated.
- **CI fixtures**: GitHub Actions runs the full test suite plus a
  smoke job that exercises the CLI against malicious + clean fixtures
  on Ubuntu and macOS.

### Changed

- **License**: MIT (was: AGPL-3.0 + commercial dual). Removes the legal-
  review friction that gated DevSecOps adoption.
- **Comparative positioning** (README): wormguard is positioned
  explicitly as defense-in-depth alongside `@lavamoat/allow-scripts`
  (sandbox), `osv-scanner`/`npm audit` (CVE), and Socket/Phylum (SaaS
  behavioral). The previous comparison table that conflated these
  categories has been removed.
- **Rule namespace**: AST-derived findings are namespaced `WG-AST-*`,
  shell-derived findings `WG-SHELL-*`, IoC-derived findings `WG-IOC-*`.
  The old single-letter regex rules (`WG-EVAL`, `WG-CHILD-PROCESS`,
  `WG-NET-DOWNLOAD`) are superseded by their AST equivalents.
- **Branding**: removed Shai-Hulud / Dune lore from README, VISION,
  ADRs. The 2025–2026 npm worm campaigns are referenced precisely
  once, in the technical context section of the VISION.

### Removed

- The "zero runtime dependency" stance. ADR-0002 explains the trade.
- The dual-license model.
- The hand-rolled lockfile parser as the only inventory source (it
  remains as a fallback for legacy formats).

### Dependencies

Runtime: `acorn`, `acorn-walk`, `shell-quote`, `ssri`, `yaml`,
`@yarnpkg/lockfile`, `sigstore`. All from official ecosystem
maintainers.

### Tests

122 tests across 15 files, all green. TS strict (`exactOptionalPropertyTypes`,
`noUncheckedIndexedAccess`) clean.

### Known limitations

Documented explicitly in the README "What it does NOT do" section. In
short: this is not a sandbox, not a CVE scanner, not a SaaS behavioral
monitor, and cannot deobfuscate arbitrary JavaScript beyond one layer of
constant folding + base64.

## [1.0.0-rc.2] — 2026-05-31

Second pass after a self-imposed "no smoke must remain" audit. Each
fix below addresses a specific gap that was identified after the
first cut shipped.

### Added

- `wormguard refresh` CLI subcommand wired to `scripts/refresh-corpus.ts`
  (the only network-touching path).
- Multi-layout inventory walker: pnpm `node_modules/.pnpm/<id>/node_modules/<pkg>`
  is now traversed and deduplicated by real path, so pnpm projects are
  fully inventoried. Symlinks (pnpm's flat surface) are followed. Bounded
  recursion handles npm v2-style nested layouts.
- Baseline v2: `scriptsHash` per package (sha256 of the lifecycle script
  bodies in canonical order). New `WG-DIFF-SCRIPT-BODY` (critical) fires
  when the script body changes for an *unchanged* version.
- v1 baselines auto-upgrade to v2 on read; the new field defaults to
  null and emits no signal until the next snapshot, so existing users
  keep working.
- `audit` subcommand now combines the baseline diff WITH a re-run of the
  full live scan pipeline, so worm-injection signatures (fingerprint
  drift, IoC matches, AST hits on the current install) gate the audit
  too — not just delta-from-baseline changes.
- `WG-YARN-PNP-NO-NODE-MODULES` (medium) advisory when a yarn-berry
  lockfile is present but `node_modules/` is absent (Plug-n-Play mode).
- `WG-IOC-NEAR` (high): names within Damerau-Levenshtein distance 1 of
  any confirmed-malicious entry are flagged as likely typosquats *of a
  known-malicious package*. Excludes legitimate top names (otherwise
  `react` would flag because `r2act` is in the corpus).
- Real cryptographic verification of npm registry signatures: bundled
  `data/npm-registry-keys.json` (fetched from
  `https://registry.npmjs.org/-/npm/v1/keys`) is used by Node's
  `createPublicKey` + `createVerify` to verify the ECDSA signature over
  `<pkg>@<ver>:<integrity>`. Tested against real fixtures
  (`sigstore@3.1.0`, `lodash@4.17.21`).
- `WG-PROVENANCE-EXPIRED-KEY` (low) and `WG-PROVENANCE-NO-KEYS` (medium)
  rules; `WG-PROVENANCE-INVALID` is emitted only when none of the
  signatures verify (critical).
- `verifyBundle` now passes a `keySelector` to `sigstore.verify` that
  resolves the bundle's `publicKey.hint` against the same bundled npm
  registry keys, enabling offline verification of `npm publish --provenance`
  bundles.
- End-to-end CLI tests against real `npm install` of small fixtures
  (`test/cli-e2e.test.ts`): clean lodash-only, synthetic malicious
  package, snapshot+audit identical, body-change diff. Skips
  gracefully when network is unavailable.
- Allowlist expanded from 28 → 59 packages (193 fingerprints), covering
  long-tail @esbuild/@img/@rollup/@next/@tailwindcss platform-specific
  binaries, electron-builder, playwright variants, simple-git-hooks,
  geckodriver/chromedriver, ws, kerberos, snappy, tree-sitter, duckdb,
  @parcel/watcher, @swc/core, lightningcss, lefthook, lint-staged,
  vite/parcel/turbo, etc.

### Changed

- `src/index.ts` cleaned: legacy `analyzeScripts` and `SCRIPT_RULES`
  remain only as `@deprecated` re-exports; canonical entry points are
  `scan`, `analyzeInstalledAst`, `inventoryFromLockfiles`,
  `verifyRegistrySignature`.
- CLI human report now shows file:line locations and a header with
  the lockfiles used and IoC corpus stats.

### Tests

154 tests across 20 files. Suite includes 7 provenance-real tests
exercising the cryptographic path against committed real-world
fixtures.
