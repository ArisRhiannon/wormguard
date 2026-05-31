# Vision — wormguard

Status: accepted. Author: Aris Rhiannon.

## One-liner

An offline, AST-grade install-script auditor for npm/pnpm/yarn/bun that
combines real JavaScript static analysis, an offline corpus of confirmed
malicious packages, sigstore provenance verification, and script-body
fingerprint drift detection — designed as a **defense-in-depth** layer
that complements (and does not replace) sandboxing, CVE scanners, or
SaaS behavioral monitors.

## Problem

Lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`)
execute with the developer's full credentials at `npm install` time. The
2025–2026 self-propagating npm worm campaigns demonstrated, repeatedly,
that an attacker who compromises a maintainer account can publish a new
version of a normally-trusted package whose injected install script
exfiltrates CI/CD secrets and continues spreading.

The free-tool landscape addresses parts of this:

- `lockfile-lint` — lockfile *hygiene* (https-only, allowed registry hosts,
  integrity present). Does not look at script content.
- `@lavamoat/allow-scripts` — *blocks* lifecycle scripts unless explicitly
  allowlisted. The right primitive for prevention, but it gives you a
  yes/no on a name; it does not tell you *what changed* or whether the
  current script body matches the historical one.
- `osv-scanner`, `npm audit` — known-CVE lookup. By definition lags zero-
  day worm campaigns.
- Socket, Phylum — SaaS behavioral analysis. Continuous, ML-driven, and
  far more powerful than any offline tool can be — at the cost of
  network dependency, account requirements, and trust in a vendor.

What was missing: an offline, deterministic, auditable tool that does
**real** static analysis of install scripts — including the JS files those
scripts actually invoke — and combines it with public-corpus IoC matching
and historical fingerprinting of known-good script bodies, producing
high-signal findings on the worm-injection pattern even on first install.

## Vision

A small, auditable, dependency-light CLI you can drop into any CI step
that says: *"this install just looks like an attack"* — with concrete
evidence (rule id, file, line, evidence snippet) and a calibrated
severity that respects the false-positive cost of native build packages.

## Principles

1. **Offline by default.** The audit pipeline never touches the network.
   The corpus refresh subcommand is the only network-touching code path.
2. **Real analysis, not pattern matching.** AST parsing with `acorn`,
   constant folding, base64 decoding, taint-source-to-sink approximation.
3. **Honest severity.** A `child_process.spawn` in `node-gyp`'s installer
   is not the same as a `child_process.spawn` in a 50-line package
   nobody has heard of. The script-fingerprint allowlist encodes that
   distinction explicitly.
4. **Defense-in-depth, not silver bullet.** The README and the docs are
   explicit about what wormguard cannot replace.
5. **Deterministic & verifiable.** Every rule is testable on fixtures.
   Findings are sorted, deduped, and stable across runs.
6. **Battle-tested dependencies.** Lockfile parsing uses the official
   ecosystem libraries (`@yarnpkg/lockfile`, `yaml` for pnpm/berry).
   Cryptography is delegated entirely to `sigstore-js` and `ssri`.
7. **Deterministic.** Pure heuristics, AST, and hash matching — identical
   inputs always produce identical findings.

## Measurable success criteria (v1.0)

- SC1: Multi-PM lockfile parsing — npm v1/v2/v3, pnpm v6/v7/v9, yarn classic,
  yarn berry, bun.lock — with priority-ordered detection. (test)
- SC2: AST analyzer detects `eval`/`new Function`/`vm.runIn*`, dynamic
  `require()`/`import()`, network builtins via aliasing, `fetch()`,
  `child_process` via destructured aliases, `process.env`, secret-path
  string literals, `Buffer.from(literal,'base64')` with decoded re-scan.
  Anti-evasion: string concatenation and template literals are folded so
  `require('ht'+'tps')` is detected. (test)
- SC3: Source-to-sink taint approximation: `env-read`/`secret-path`/`crypto-
  key-read` reaching `network-builtin`/`fetch`/`child-process`/`shell-pipe`
  escalates severity one rung. (test)
- SC4: IoC corpus — bundled `data/iocs.json` with the GHSA `type=malware`
  npm name set (≥10 000 entries) and a curated set of well-attested C2
  hostnames; refreshable via `bun run refresh-corpus`. (test)
- SC5: Script-fingerprint allowlist — `data/script-allowlist.json` with
  ≥50 known-good lifecycle-script body sha256s across ≥20 widely-used
  native packages, populated from the npm registry packument. A package
  whose body matches an accepted hash has its findings suppressed; a
  package in the allowlist with a non-matching hash emits
  `WG-SCRIPT-FINGERPRINT-DRIFT` (critical). (test)
- SC6: Provenance: read npm v9+ `signatures` and `dist.attestations` from
  `package-lock.json`; provide `verifyBundle()` API delegating to
  `sigstore-js` for offline cryptographic verification of supplied
  bundles. (test)
- SC7: Granular config — per-package, per-rule, optional script-hash
  allowlist that *does not* apply when the script changes. The legacy
  whole-package switch is parsed for backward compatibility but is
  documented as deprecated. (test)
- SC8: Baseline diff — snapshot + audit detect added/removed packages,
  version changes, integrity changes for an unchanged version, and
  packages that gained a lifecycle script. (test)
- SC9: CLI `scan`/`snapshot`/`audit`/`refresh` with `--json`, `--ci`,
  `--baseline`, `--out` flags; exit code respects `failSeverity`. (test)
- SC10: Comprehensive test suite — anti-evasion (string concat, template
  literals, base64 decoded), false-positive guards (benign tsc, native
  builds), end-to-end orchestration (allowlist suppression, drift
  escalation, IoC domain match, parse fallback). (test)

## Scope (v1)

Multi-PM lockfile inventory; AST + taint analyzer; IoC corpus + refresh
subcommand; script-fingerprint allowlist with populator; provenance
context + sigstore verification; baseline diff; typosquat; integrity /
registry policy; granular config; CLI + JSON + CI codes; ≥120 tests.

## Non-goals (v1)

- Sandboxing, blocking installs, or runtime interception (out of scope:
  `@lavamoat/allow-scripts` is the right tool).
- A vulnerability database (out of scope: `osv-scanner` is the right tool).
- Continuous registry-wide behavioral monitoring (out of scope:
  Socket/Phylum are the right tools).
- Full deobfuscation of arbitrary JS / complete data-flow analysis
  (best-effort; we fold one layer of concat + base64 and approximate
  taint).
- Learned or statistical detection models (every rule here is hand-written
  and deterministic).

## Definition of done

SC1–SC10 met, all tests green, TS strict clean, CI green, MIT-licensed
release published. README, VISION, ADRs honest about scope and
limitations.
