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

## [1.0.0-rc.5] — 2026-05-31

### Added

- **`WG-NO-PREVENTION-LAYER`** (low) advisory: when a lockfile is
  detected (project actually installs deps) but no install-time
  prevention layer is configured. Detected layers:
  `@lavamoat/allow-scripts` in dependencies (or `lavamoat.allowScripts`
  in `package.json`), `ignore-scripts=true` in `.npmrc` or
  `npmrc.json`, `enableScripts: false` in `.yarnrc.yml`, or
  pnpm `onlyBuiltDependencies` in `package.json`. wormguard reports
  findings; a complete defense in depth requires a prevention layer.
- **`wormguard emit-allow-scripts [dir] [--out FILE]`** subcommand.
  One-shot config bridge from wormguard's bundled script-fingerprint
  allowlist to LavaMoat's `lavamoat.allowScripts` schema. Default
  deny: only packages whose lifecycle scripts match a known-good
  fingerprint (or a user-supplied `scriptFingerprints` entry) become
  `allow: true`. Drift on a known package becomes `allow: false`
  (the worm-injection signal carries through). Output goes to stdout
  by default, or to `--out FILE`.

### Changed

- README §Roadmap: out-of-scope clarified — wormguard does NOT plan
  to integrate with LavaMoat at the runtime level. They coexist
  cleanly as separate layers (LavaMoat = prevention, wormguard =
  detection + config bridge).

### Tests

216 pass, 0 fail. 12 new tests covering the prevention-layer detector
(7 layer combinations) and the emit-allow-scripts bridge (5 cases
including drift-as-deny).



Closes red-team P1 (AST evasions) and P2 (FP / robustness) findings.

### P1 — 18 AST evasions closed

The red-team identified 18 patterns that bypassed the v1 AST analyzer. The
analyzer is now a two-pass walker: pass 1 collects aliases (`const r =
require`), pass 2 detects sinks consulting that alias table.

New / improved detections:

- `(0, eval)('...')` SequenceExpression with eval-alias tail (H1)
- `globalThis.eval` / `globalThis.Function` / `global.eval` direct (H2)
- Function constructor via prototype chain `({}).constructor.constructor` and `[].constructor.constructor`, both as alias init RHS and as direct call site (H3, H4)
- Alias propagation through `const r = require`, `const r = globalThis.require`, `const F = Function` etc. — every call to a known-alias is now treated as the underlying primitive (H5, H6)
- `Reflect.apply(eval, null, [...])` (H7)
- `eval.call/apply/bind(...)`, `globalThis.eval.call(...)`, `globalThis.fetch.call(...)` and any chain ending in `.call|.apply|.bind` rooted at an eval/fetch alias (H8, H16)
- `import('https')` and `import('htt'+'ps')` dynamic ESM with constant folding (H9, H10, H11)
- `new Worker(src, {eval:true})` — both the Worker call and the inline source are scanned (H12)
- `process.binding('http_parser')` (H13)
- `process.dlopen({...}, '/path/to.so')` native shared object load (H14)
- `module.constructor._load('child_process').exec(...)` — Node's internal `_load` is a documented worm technique and is now treated identically to `require` (H15)
- `process[String.fromCharCode(0x65, 0x6e, 0x76)]` — computed property where the key folds to "env" (H18)

`foldString` now folds numeric `String.fromCharCode(...)` arguments and
`memberPath` canonicalizes through `SequenceExpression` and
`ParenthesizedExpression`. 22 dedicated tests in
`test/ast-evasions-h1-h18.test.ts`.

### P2 — Robustness fixes

- **M1 worm-propagate rule**: a lifecycle script that writes to
  `package.json` AND invokes `npm publish` (directly or via
  `execSync('npm publish ...')` / `spawnSync('npm', ['publish', ...])`)
  emits `WG-WORM-PROPAGATE` (critical). This is the canonical
  Shai-Hulud-style self-propagation primitive and was previously only
  flagged as `medium` `child-process` + `medium` `fs-write-outside`.
- **M2 typosquat length floor**: short legitimate names (`ms`, `fs`,
  `os`, etc.) no longer flag `WG-TYPOSQUAT`. The new rule requires
  name length ≥ 4 for distance-1 firing and ≥ 6 for distance-2.
  `lodaash` (length 7, distance 1 of `lodash`) still flags.
- **M3 atomic baseline writes**: `wormguard snapshot` writes via a
  temp-file in the same directory, then `renameSync` to the final
  path. Concurrent snapshot invocations no longer leave a baseline
  file half-written.
- **M4 TOCTOU narrowing**: `detectLockfiles` returns the file content
  alongside the path. Callers no longer re-read; the second-read
  race window is closed.
- **M5 NUL byte sanitization**: `snip()` (used for evidence strings)
  escapes NUL and ASCII control characters as `\0` / `\x07` etc. so
  malicious package.json entries with embedded control chars don't
  produce broken JSON consumers or terminal-corruption artifacts.

204 pass, 0 fail. TS strict clean.



Self-imposed red-team pass. Four CRITICAL design issues found, fixed,
and tested.

### C1 — Configuration trust model (CRITICAL)

`.wormguard.json` is no longer read from the scanned tree by default.
The previous design was a confused deputy: an attacker who landed a
malicious dep also landed the config that audited it (`failSeverity:low`,
`ignoreRules:[everything]`, or `scriptFingerprints[attacker-sha]` would
silently kill the scanner).

- Config now loads from `--config FILE` (CI-controlled) or the
  `WORMGUARD_CONFIG` env var.
- An in-repo `.wormguard.json` emits `WG-CONFIG-IN-REPO-IGNORED` (low)
  so operators see it.
- Pass `--trust-repo-config` to opt back into the v0 behavior for
  local development. Documented as **do-not-use-in-CI**.
- New `WG-CONFIG-MISSING` (medium) when `--config FILE` points at a
  missing/invalid file.

### C2 — IoC matching is now version-range aware (CRITICAL)

Previous schema kept only package names from the GHSA `type=malware`
feed. A package whose history included one compromised version was
flagged critical forever (e.g. `ansi-regex`, `chalk`, `strip-ansi`).
This produced critical FPs on legitimately-recovered installs.

- `scripts/refresh-corpus.ts` now extracts `vulnerable_version_range`
  per advisory.
- `data/iocs.json` schema upgraded to v2 with `ranges:
  Record<name, string[]>`. Re-fetched: 23 055 names, 23 055 with
  explicit ranges, 1.7 MB. Examples: `ansi-regex` → `["= 6.2.1"]`,
  `chalk` → `["= 5.6.1"]`, `strip-ansi` → `["= 7.1.1"]`.
- `matchPackageName(name, version)` uses `semver.satisfies` to verify
  the installed version is inside an affected range before firing
  `WG-IOC-NAME` (critical).
- A name in the corpus without a concrete range (or with only the
  catch-all `>= 0`) yields `WG-IOC-NAME-LEGACY` (medium) instead.
- Adds `semver` (the official npm semver library) as a runtime dep.

### C3 — Lockfile DoS via deeply-nested `dependencies` (CRITICAL)

`fromDependencies` was recursive; a `package-lock.json` v1 with 20 000
levels of nesting triggered `RangeError: Maximum call stack size
exceeded`, crashing the scanner. A hostile lockfile in the scanned
tree was a trivial DoS.

- Rewritten as iterative BFS with a 256-level depth bound.
- Throws `WormguardError` on excessive depth instead of stack-overflow.
- Test confirms 200-level lockfile parses cleanly; 10 000-level
  lockfile is rejected as `WormguardError`.

### C4 — `verifyBundle` confused-deputy (CRITICAL)

`verifyBundle(pkg, bundleJson, payload)` only verified the cryptographic
signature over the payload bytes. It did not check that the bundle's
DSSE statement subject matched `pkg@version`, or that the subject
digest matched the expected payload digest. A valid bundle for a
package the attacker controls could be presented as evidence for a
victim package.

- Required parameters: `expectedSubjectName`, optional `expectedDigest`.
- After the cryptographic verify succeeds, the DSSE envelope is
  decoded and the `subject[].name` is matched against
  `expectedSubjectName`. Mismatch → critical
  `WG-PROVENANCE-INVALID`.
- If `expectedDigest` is supplied, the subject's `sha512` (or
  `sha256`) digest must match. Mismatch → critical.
- Bundles without a DSSE envelope (signature-only mode) cannot be
  bound to a package identity and are rejected.
- Tests use real npm provenance fixtures (`sigstore@3.1.0`) committed
  under `test/fixtures/provenance/` to prove cross-package and
  cross-artifact replay are rejected.

### Tests

169 pass, 0 fail across 22 files. TS strict clean.

### Migration

Existing users with an in-repo `.wormguard.json` will start seeing the
file ignored. Three options:

1. (Recommended) Move the file outside the scanned tree and pass
   `--config /path/to/it`. Set up via your CI runner's environment.
2. Set `WORMGUARD_CONFIG=/abs/path` in the CI environment.
3. (Local dev only) Pass `--trust-repo-config` to opt back in.



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
