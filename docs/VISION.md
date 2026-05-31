# Vision — wormguard

Role: CEO. Author: Aris Rhiannon. Status: accepted.

## One-liner
`wormguard` — an **offline, zero-dependency** npm supply-chain auditor that catches malicious
dependency installs **behaviorally and by change-detection**, with **no network, no account, and no
CVE database**. A tripwire for the install step: it flags the exact technique the 2025–2026
"Shai-Hulud" worms use — packages that suddenly gain a `preinstall`/`postinstall` script that steals
CI/CD secrets — *before* you run it.

## Problem
The npm supply chain is under active, self-propagating attack (Shai-Hulud 2025; Mini Shai-Hulud
Apr–May 2026 compromised 160→600+ packages incl. TanStack, Mistral AI, SAP namespaces). The vector:
malicious lifecycle scripts injected into **new versions of previously-trusted packages**, exfiltrating
secrets at `npm install` time. Existing free tools address adjacent problems: `lockfile-lint` (lockfile
hygiene), `@lavamoat/allow-scripts` (manual allowlist), `OSV-Scanner`/`CVE Lite` (known CVEs, need a DB),
`socket`/Aikido (SaaS, network, accounts). None do **offline, zero-DB, behavioral + baseline-diff**
detection that catches the *zero-day* worm.

## Vision
The default `npm install` tripwire: a tiny, auditable, dependency-free CLI you can drop into any
project or CI step that says "this install just changed in a way that looks like an attack" — without
phoning home.

## Principles
1. **Offline & zero-DB.** No network, no telemetry, no CVE feed. Detection is behavioral + differential.
2. **Zero runtime deps.** Only the platform stdlib. Tiny and auditable.
3. **Deterministic & verifiable.** Every rule is pass/fail testable on fixtures.
4. **Low false-positive by design.** Severity tiers + allowlist + the high-signal baseline-diff.
5. **Honest.** Defense-in-depth / early-warning, not a guarantee; documented threat model.
6. **No AI.** Pure heuristics and structural diffing.

## Measurable success criteria (v1.0)
- SC1: Parse `package-lock.json` (lockfile v2 and v3) into a normalized package inventory
  (name, version, resolved, integrity, registry host, hasInstallScript, dev flag). (test)
- SC2: Walk `node_modules` and extract each package's lifecycle scripts
  (preinstall/install/postinstall/prepare) package-manager-agnostically. (test)
- SC3: The lifecycle-script analyzer flags a curated set of malicious patterns (shell-out, `curl|sh`,
  `child_process`, network, `process.env`/secret-path access, base64/eval/obfuscation) with correct
  severities, and does NOT flag benign scripts (e.g. `tsc -b`). (test, both directions)
- SC4: A baseline snapshot can be written and re-read byte-stably; an `audit` against it flags a
  **newly-introduced install script**, a version/integrity/resolved/registry change, and added
  packages — and reports NO changes when nothing changed. (test)
- SC5: Typosquat detection flags names within Damerau-Levenshtein distance ≤2 of a bundled popular-name
  list (excluding exact matches), and does not flag unrelated names. (test)
- SC6: Integrity/registry policy flags non-https `resolved`, disallowed registries, and missing
  integrity; respects an allowlist. (test)
- SC7: CLI `scan`/`snapshot`/`audit` support `--json` and `--ci`; exit code is 0 on a clean project and
  non-zero when findings ≥ the fail threshold; a `.wormguard.json` allowlist suppresses chosen rules. (test)
- SC8: Zero runtime dependencies; `bun test` green; `tsc` strict clean; CI passes; README documents the
  model, threat model, the full rule table, and runnable examples.

## Scope (v1)
npm `package-lock.json` (v2/v3) inventory + `node_modules` script extraction; behavioral rule engine;
baseline snapshot + diff; typosquat; integrity/registry policy; `.wormguard.json`; CLI + JSON + CI codes.

## Non-goals (v1)
- pnpm / yarn / bun lockfile parsing (roadmap; `node_modules` scan already covers their scripts).
- Network calls, registry lookups, or a vulnerability/CVE database of any kind.
- Sandboxing/blocking installs (we detect & report; blocking is the user's CI gate).
- Deobfuscating arbitrary JS / full taint analysis (heuristics only).
- Any AI/ML.

## Definition of done
SC1–SC8 met and independently validated (VALIDATION.md), QA findings addressed, pushed to GitHub under
ArisRhiannon with the AGPL-3.0 + commercial source-available license, CI green.
