# wormguard

[![ci](https://github.com/ArisRhiannon/wormguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/wormguard/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/badge/npm-1.0.0--rc.1-orange.svg)](https://www.npmjs.com/package/wormguard)

An offline, AST-grade install-script auditor for npm, pnpm, yarn (classic +
berry), and bun. It performs real JavaScript AST analysis with a small
taint approximation, matches against an offline corpus of confirmed
malicious npm packages (~23k names from the GitHub Advisory Database) and
known C2/exfil endpoints, fingerprints lifecycle scripts of widely-used
native packages so legitimate `postinstall` work doesn't drown the report,
and detects the Shai-Hulud-class injection pattern (a normally-trusted
package whose install script body suddenly differs from any known-good
fingerprint).

This is not a sandbox, not a CVE scanner, and not a SaaS-backed behavioral
monitor. It is **defense-in-depth** designed to sit alongside those tools.

## What it actually does

| Layer | Mechanism | Catches |
|------|-----------|---------|
| Lockfile inventory | Parsers for npm v1/v2/v3, pnpm v6/v7/v9, yarn classic via `@yarnpkg/lockfile`, yarn berry, bun.lock JSONC | Package set, integrity, registry hosts, `hasInstallScript` flag |
| Lifecycle command parsing | `shell-quote` tokenization across `&&`, `\|\|`, `;`, `\|`; resolves `node ./script.js` and `node -e "…"` | curl\|sh download-and-run, base64 decode in shell, `eval`/`source`, network tools (curl/wget/nc) |
| AST analysis | `acorn` (the parser used by webpack/rollup/eslint) with `acorn-walk`, plus a regex fallback for unparseable sources | `eval` / `new Function` / `vm.runIn*`, dynamic `require()`/`import()`, `require('http'\|'https'\|…)`, `fetch()`, `child_process.*` via destructured aliases, `process.env` reads, secret-path string literals |
| Anti-evasion | Constant folding for `+`, template literals; decodes `Buffer.from(literal, 'base64')` and `atob(literal)` then re-scans the decoded text | `require('ht' + 'tps')`, `` require(`${x}https`) ``, base64-encoded secret paths and network builtin strings |
| Taint approximation | Source categories (`env-read`, `secret-path`, `crypto-key-read`) reaching sink categories (`network-builtin`, `fetch`, `child-process`, `shell-pipe`) escalates severity one rung | `process.env.NPM_TOKEN` flowing into a `fetch()`/`https.request()` |
| IoC corpus | Bundled `data/iocs.json` from the public GHSA `type=malware&ecosystem=npm` feed (~23 000 names, refreshable via `bun run refresh-corpus`) plus a curated set of well-attested C2/exfil hostnames | First-install of a confirmed-malicious npm package even with no baseline |
| Script-fingerprint allowlist | `data/script-allowlist.json` of sha256s of the lifecycle-script *body strings* of 28 widely-used native packages (esbuild, sharp, prisma, bcrypt, husky, electron, playwright, …) across all non-deprecated versions | A worm that replaces the install script of a normally-trusted package — the exact fingerprint *drift* is reported as critical |
| npm provenance | Reads `signatures` (registry ECDSA) and `dist.attestations` (sigstore build provenance) from `package-lock.json`. Optional `verifyBundle()` API runs sigstore-js verification on a user-supplied bundle | Missing/no-attestation → low advisory; explicit verification failure → critical |
| Baseline diff | Snapshot of inventory + script hashes; `audit` flags newly-added packages, version changes, integrity changes for the same version, and packages that gained a lifecycle script | Tampering on upgrade |

## What it does NOT do

- **It is not a sandbox.** It does not block or intercept `npm install`. To
  actually prevent a malicious script from running, use
  [`@lavamoat/allow-scripts`](https://github.com/LavaMoat/LavaMoat/tree/main/packages/allow-scripts)
  or `npm`'s own `ignore-scripts`. wormguard is the auditor that decides
  whether a given lifecycle script *should* be allowed.
- **It is not a CVE scanner.** It does not consult NVD/OSV for known
  vulnerable versions. Use [`osv-scanner`](https://github.com/google/osv-scanner)
  or `npm audit` for that axis.
- **It is not a SaaS behavioral monitor.** Tools like
  [Socket](https://socket.dev/) and [Phylum](https://www.phylum.io/) ingest
  the entire registry continuously and apply ML/behavioral models that no
  offline tool can match. wormguard's value is precisely that it is small,
  auditable, deterministic, and runs anywhere.
- **It cannot deobfuscate arbitrary JavaScript.** It folds simple string
  concatenation and one layer of base64; it does not constant-fold
  arbitrary expressions, evaluate the program, or trace data flows across
  function calls. A determined attacker can still hide a payload from
  pure static analysis.

## Limits and bypasses (read this before depending on it)

This is **static AST analysis with a small taint approximation**. It is
not behavioral observation, not symbolic execution, and not a sandbox.
The pipeline is high-leverage against *opportunistic* supply-chain
attacks — the kit-built worm payloads typical of the 2025–2026 npm
campaigns, where the same payload is sprayed across dozens of compromised
packages and has not been tuned to evade any specific tool. It is
**derivable-around** by an attacker who has read this README. Concretely:

- **Variable-resolved `require()`/`import()`** — `const m = process.env.X;
  require(m)` is flagged as `WG-AST-DYNAMIC-REQUIRE` (medium), but I do
  not resolve `m`. If `process.env.X` was set elsewhere by the same
  script, I do not follow that flow.
- **Native binaries shelled out from a lifecycle script** — if
  `postinstall` runs `./bin/payload` and the payload is a compiled ELF
  or Mach-O, I do not analyze binaries. The fingerprint-drift check
  still catches modifications to the *script* body, but a binary
  payload that has always been there will not trigger me on its own.
- **Multi-stage decode chains** — I unwrap one layer of
  `Buffer.from(literal, 'base64')` and re-scan. A two-layer chain
  (base64 inside hex inside …) is not unwrapped.
- **Off-host fetched payloads** — `curl https://x | sh` flags
  `WG-SHELL-PIPE` (critical) at the shell level, but I do not fetch
  the URL or inspect what would arrive over the wire. A payload that
  is *fetched but not piped* (`curl -o /tmp/x; node /tmp/x`) flags
  `WG-SHELL-NET-DOWNLOAD` (high) and the subsequent `node /tmp/x`
  reads `/tmp/x` if it exists at scan time, but if the URL is fetched
  at install time only the shell command is visible at scan time.
- **Timing/conditional payloads** — `if (Date.now() > X) malicious()`
  is detected if the AST hits the malicious branch. Static analysis
  has no notion of `Date.now()` returning anything; the malicious
  branch is always reachable to me.
- **The threat model assumes the rules are public.** They are. An
  attacker that knows the rule list can construct a payload that hits
  no rule. This is the structural limit of any heuristic-based detector
  with public rules, including, in different ways, every other free
  tool in this space. Mitigations: pair with a sandbox
  (`@lavamoat/allow-scripts` or `npm install --ignore-scripts`), pair
  with a CVE scanner (`osv-scanner`), and treat wormguard as a
  defense-in-depth tripwire, not a guarantee.

If your threat model includes targeted attackers who have specifically
prepared a payload to evade wormguard, you need runtime sandboxing.
This tool does not provide that.

## Where it fits

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  osv-scanner /   │  │   LavaMoat       │  │   Socket /       │
│  npm audit       │  │   allow-scripts  │  │   Phylum         │
│  (CVE database)  │  │  (sandbox/block) │  │  (SaaS behavior) │
└────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
         │                     │                     │
         └──────────┐    ┌─────┴──────┐    ┌─────────┘
                    │    │            │    │
                    ▼    ▼            ▼    ▼
              ┌──────────────────────────────┐
              │         wormguard            │
              │  offline AST + IoC corpus +  │
              │  script fingerprints         │
              │  (defense-in-depth tripwire) │
              └──────────────────────────────┘
```

## Install

```sh
bun add -d wormguard           # or: npm i -D wormguard / pnpm add -D wormguard
```

Requires Node ≥ 20 or Bun ≥ 1.1.

## Use

```sh
# 1) Scan: AST + IoC + provenance + policy + typosquat
wormguard scan .                    # human report
wormguard scan . --json             # machine-readable
wormguard scan . --ci               # exit non-zero if anything ≥ fail severity (default: high)

# 2) Pin a baseline; later, audit for compromise-shaped changes
wormguard snapshot .                # writes .wormguard-baseline.json
wormguard audit . --ci              # exit non-zero on a worm-shaped diff

# 3) Refresh the bundled IoC corpus (the ONLY network-touching command)
GITHUB_TOKEN=…  wormguard refresh   # or: bun run refresh-corpus
```

Drop `wormguard scan . --ci` into your pipeline right after `npm ci` /
`pnpm install` / `yarn install`.

## Configuration — `.wormguard.json`

```json
{
  "allowedHosts": ["registry.npmjs.org", "npm.mycorp.example"],
  "allowMissingIntegrity": false,
  "ignoreRules": ["WG-INVENTORY-ADDED"],
  "failSeverity": "high",

  "scriptAllowlist": [
    {
      "package": "my-internal-tool",
      "rules": ["WG-AST-CHILD-PROCESS"],
      "scriptSha256": "e3b0c4429842…"
    }
  ],

  "scriptFingerprints": {
    "my-internal-tool": [
      "e3b0c4429842c4498…known-good-postinstall-hash",
      "9f86d081884c7d6594…known-good-prepare-hash"
    ]
  }
}
```

Granularity is intentional: `scriptAllowlist` allows `rule X` for `package
Y`, optionally bound to a specific script-body hash. If the package's
script changes, the suppression no longer applies — which is exactly what
you want.

The legacy `allowInstallScripts: ["pkg-a", "pkg-b"]` (whole-package
suppression) is parsed for backward compatibility and emits a deprecation
notice.

## Rule reference

| id | severity | meaning |
|----|----------|---------|
| WG-IOC-NAME | critical | package name appears in the GHSA `type=malware` corpus |
| WG-IOC-NEAR | high | package name is 1 edit from a confirmed-malicious npm package (likely typosquat *of* a known-malicious package) |
| WG-IOC-SCRIPT-HASH | critical | sha256 of a lifecycle script body matches a known-malicious fingerprint |
| WG-IOC-DOMAIN | critical | lifecycle script source references a known C2/exfil hostname |
| WG-SCRIPT-FINGERPRINT-DRIFT | critical | known-good package whose lifecycle-script body hash differs from every accepted fingerprint (worm-injection signature) |
| WG-SHELL-PIPE | critical | lifecycle command pipes content into a shell |
| WG-AST-SHELL-PIPE | critical | inline JS inside `node -e …` pipes into a shell |
| WG-DIFF-INTEGRITY | critical | integrity changed for the same version (content tampering) |
| WG-DIFF-SCRIPT-BODY | critical | lifecycle script BODY changed for the same version (worm-injection on disk) |
| WG-PROVENANCE-INVALID | critical | sigstore or registry-signature verification failed |
| WG-AST-EVAL | high (→critical with taint) | `eval` / `new Function` / `vm.runIn*` |
| WG-AST-CONCAT-EVAL | high | feeds a non-literal value to eval (obfuscation) |
| WG-AST-NETWORK-BUILTIN | high (→critical with taint) | `require('http'/'https'/'net'/'tls'/'dns'/'dgram')` |
| WG-AST-FETCH | high (→critical with taint) | `fetch()` |
| WG-AST-SECRET-PATH | high | string literal references `.npmrc`/`.aws`/`.ssh`/`.netrc`/`id_rsa`/etc |
| WG-AST-CRYPTO-KEY | high | reads/uses cryptographic private-key material |
| WG-SHELL-NET-DOWNLOAD | high | curl/wget/nc invoked from the lifecycle command |
| WG-SHELL-EVAL | high | shell-level `eval` or `source` |
| WG-DIFF-NEW-SCRIPT | high | package gained a lifecycle script since baseline |
| WG-DIFF-REGISTRY | high | resolved URL / registry host changed for the same version |
| WG-INSECURE-RESOLVED | high | resolved over `http://` |
| WG-TYPOSQUAT | high/medium | name within Damerau-Levenshtein 1–2 of a popular package |
| WG-AST-CHILD-PROCESS | medium (→high with taint) | spawns a child process |
| WG-AST-FS-WRITE | medium | writes to the filesystem |
| WG-AST-BASE64 | medium | decodes base64 (decoded body is re-scanned for further indicators) |
| WG-AST-DYNAMIC-REQUIRE | medium | `require()`/`import()` with non-literal argument |
| WG-AST-PARSE-FAILED | medium | acorn could not parse; regex fallback used |
| WG-SHELL-BASE64 | medium | shell-level `base64 -d` / `openssl enc -d` |
| WG-NO-INTEGRITY | medium | missing integrity hash |
| WG-UNKNOWN-REGISTRY | medium | resolved from a non-allowed registry host |
| WG-AST-ENV-READ | low (→medium with taint) | reads `process.env` |
| WG-INSTALL-SCRIPT | low | advisory: package defines lifecycle scripts |
| WG-INSTALL-SCRIPT-ALLOWLISTED | low | every lifecycle body matches a bundled known-good fingerprint |
| WG-PROVENANCE-MISSING | low | no registry signatures and no build provenance |
| WG-PROVENANCE-NO-ATTESTATION | low | registry-signed but no `npm publish --provenance` attestation |
| WG-PROVENANCE-EXPIRED-KEY | low | registry signature verifies, but the signing key has since expired |
| WG-PROVENANCE-NO-KEYS | medium | bundled npm registry public keys are unavailable; cannot verify |
| WG-YARN-PNP-NO-NODE-MODULES | medium | yarn-berry lockfile present but no `node_modules` (PnP mode) |
| WG-DIFF-ADDED / -REMOVED / -VERSION | low | inventory changes since baseline |

## Library API

```ts
import { scan, snapshot, diff, inventoryOf, meetsFail } from "wormguard";
import { matchPackageName, matchDomains } from "wormguard/corpus";

const { findings, counts, lockfilesUsed } = scan(process.cwd());
if (meetsFail(findings, "high")) process.exit(1);

// Direct corpus matching (offline, no network):
matchPackageName("definitely-malicious-pkg"); // → critical Finding | null
matchDomains(sourceText);                     // → string[] of IoC domains
```

## Threat model

wormguard catches:

- A *new* version of a previously-trusted package whose install script body
  has changed away from any known-good fingerprint (the worm-injection
  signature: `WG-SCRIPT-FINGERPRINT-DRIFT`).
- An install script that — after AST-based deobfuscation — uses
  `eval`/`new Function`, dynamic `require()`, network builtins, `fetch()`,
  `child_process`, secret-path literals, or cryptographic key reads.
- An install script whose execution chain reaches a network sink with a
  source from `process.env`/secret paths/private keys (taint escalation).
- A lifecycle command that pipes a download into a shell, base64-decodes
  in shell, or runs `eval`/`source`.
- A package whose name appears in the GHSA `type=malware` corpus
  (≈23 000 entries, refreshable).
- A lifecycle source referencing a known C2/exfil hostname.
- A baseline diff: new install script, integrity change for an unchanged
  version, registry change, added/removed/version-changed packages.
- An npm package without provenance attestation (low advisory; combined
  with a lifecycle script in a worm-target name space, the score adds up).

It does **not** catch:

- A known-CVE in a package whose installation looks normal (use
  `osv-scanner` / `npm audit`).
- Malicious behavior triggered at *runtime* rather than at install time
  (use Socket/Phylum, or LavaMoat at runtime).
- Heavily obfuscated JS payloads beyond one layer of constant folding +
  base64.
- Anything that requires sandboxing or blocking; wormguard reports, your
  CI gate decides.

## How verification works (and what does NOT happen)

The 154 tests are committed at `test/*.test.ts` and are reproducible by any
clone with `bun test`. The CI workflow runs them on Ubuntu and macOS on
every push/PR. Real-world fixtures used by the cryptographic-verification
tests (`test/fixtures/provenance/sigstore-3.1.0.json`,
`test/fixtures/provenance/lodash-4.17.21.json`) are committed bytes
captured from the public npm registry — anyone can re-fetch them and
diff to confirm they have not been tampered with.

There is **no AI self-validation** in this project. Earlier drafts of the
repository contained an automated "validator" report produced by the same
agent that wrote the code; that file was deleted in v1 because an
automated validator validating itself is not independent in any useful
sense. The current verification surface is:

1. The committed test suite (`bun test`).
2. The committed real-world fixtures used by the cryptographic
   verification tests.
3. The CI workflow that re-runs both on a clean machine on every push.
4. The bundled reference data files (see the next section), each with a
   top-level `fetchedAt` field documenting when they were regenerated.

If you want a third-party audit, run the test suite yourself, diff the
fixtures against the public registry, and read the rules in
`src/ast/analyzer.ts` and `src/ast/orchestrate.ts`. Every rule is small
enough to read and has a corresponding test.

## Reference data (provenance and refresh)

| File | Source | Refresh command |
|------|--------|-----------------|
| `data/iocs.json` | GitHub Advisory Database (`type=malware&ecosystem=npm`) via the public REST API | `bun run refresh-corpus` |
| `data/script-allowlist.json` | npm registry packument for ~60 curated packages with legitimate lifecycle scripts; sha256 of every distinct script body across non-deprecated versions | `bun run refresh-allowlist` |
| `data/top-names.json` | [ecosyste.ms](https://packages.ecosyste.ms) "most depended on" view of the npm registry (sorted descending by dependent-package count); used as typosquat reference targets | `bun run refresh-top-names` |
| `data/npm-registry-keys.json` | `https://registry.npmjs.org/-/npm/v1/keys` (npm registry's public ECDSA P-256 signing keys); used to verify per-package registry signatures | manual re-fetch when npm publishes a new key |

All four data files have a top-level `fetchedAt` ISO timestamp and a
`source` field (where applicable) documenting their public origin. The
refresh scripts are the *only* network-touching code in the project.

## Status & roadmap

V1 (this branch): AST analyzer, IoC corpus (GHSA), provenance reader and
sigstore verifier, script-fingerprint allowlist with drift detection,
multi-PM lockfile parsing, granular config, baseline diff, typosquat,
integrity/registry policy, CLI + JSON + CI codes.

Roadmap:

- Sigstore bundle auto-discovery from local npm cache.
- Optional online enrichment (`wormguard scan --online` to fetch
  attestations from the registry and verify them in-line).
- Bigger curated allowlist (community-driven).
- Bigger curated IoC corpus (community-driven).
- pnpm/yarn `hasInstallScript` extraction (currently filled in by the
  node_modules walker; we can read it from each PM's metadata too).

## License

MIT. See [LICENSE](LICENSE).
