# wormguard

[![ci](https://github.com/ArisRhiannon/wormguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/wormguard/actions/workflows/ci.yml)
[![License: AGPL-3.0 + Commercial](https://img.shields.io/badge/license-AGPL--3.0%20%2B%20Commercial-blue.svg)](LICENSE)

**An offline, zero-dependency npm supply-chain auditor.** It catches malicious dependency installs
**behaviorally and by change-detection** — *no network, no account, and no CVE database*. wormguard is a
tripwire for the `npm install` step: it flags the exact technique the 2025–2026 **Shai-Hulud** worms use
— a package that suddenly gains a `preinstall`/`postinstall` script that exfiltrates CI/CD secrets —
*before* you run it.

## Why

CVE scanners look up *known* bad versions; they lag the worm. SaaS scanners need a network and an
account. wormguard is different: it reads your lockfile + `node_modules` locally and reasons about
**behavior** (what install scripts do) and **change** (what just got added or mutated) — so it catches
*zero-day* supply-chain attacks with no database to update and nothing phoned home.

| Tool | Approach | Network | DB |
|------|----------|---------|----|
| `lockfile-lint` | lockfile hygiene (hosts/https/integrity) | no | no |
| `@lavamoat/allow-scripts` | manual allowlist of scripts | no | no |
| `osv-scanner` / `cve-lite` | known CVE lookup | mode-dependent | **yes** |
| socket / Aikido | SaaS behavioral | **yes** | yes |
| **wormguard** | **behavioral + baseline-diff** | **no** | **no** |

## Install

```sh
bun add -d wormguard      # or: npm i -D wormguard   (Node >= 20)
```

## Use

```sh
# 1) Audit what you have right now (scripts + typosquats + provenance)
wormguard scan .                 # human report
wormguard scan . --json          # machine-readable
wormguard scan . --ci            # exit non-zero if anything >= "high"

# 2) Pin a known-good baseline, then detect malicious CHANGES on every install/CI run
wormguard snapshot .             # writes .wormguard-baseline.json
wormguard audit . --ci           # exits non-zero if a dep gained an install script,
                                 # or integrity/registry changed for the same version
```

Drop `wormguard audit . --ci` into your pipeline right after `npm ci`.

## Threat model

wormguard detects **changes and behaviors consistent with a supply-chain compromise**: a newly-injected
install script (the worm signature), a script that shells out / downloads / reads secrets / enumerates
env vars, a same-version integrity or registry change (content tampering), a typosquatted name, and
insecure provenance. It is **defense-in-depth / early warning**, not a guarantee: heuristics can be
evaded and it does not sandbox or block installs (your CI gate does, via the exit code). It performs no
network, telemetry, or code execution — it only reads files.

## Rules

| id | severity | meaning |
|----|----------|---------|
| WG-SHELL-PIPE | critical | install script pipes content into a shell (download-and-run) |
| WG-DIFF-INTEGRITY | critical | integrity changed for the **same** version (tampering) |
| WG-NET-DOWNLOAD | high | curl/wget/nc… in an install script |
| WG-CHILD-PROCESS | high | spawns child processes during install |
| WG-EVAL | high | eval / dynamic code execution |
| WG-SECRET-PATH | high | references `.npmrc`/`.aws`/`.ssh`/`.env`… |
| WG-DIFF-NEW-SCRIPT | high | package **gained** an install script since baseline (worm signature) |
| WG-DIFF-REGISTRY | high | resolved URL / registry changed for the same version |
| WG-INSECURE-RESOLVED | high | resolved over `http://` |
| WG-TYPOSQUAT | high/med | name is 1–2 edits from a popular package |
| WG-ENV-ENUM | medium | reads `process.env` during install |
| WG-BASE64 | medium | base64 decode (possible obfuscation) |
| WG-SELF-PROPAGATE | medium | writes into `node_modules/` paths |
| WG-UNKNOWN-REGISTRY | medium | resolved from a non-allowed registry host |
| WG-NO-INTEGRITY | medium | missing integrity hash |
| WG-DIFF-ADDED / -REMOVED / -VERSION | low | inventory changes since baseline |
| WG-INSTALL-SCRIPT | low | advisory: package defines lifecycle scripts |

## Config — `.wormguard.json`

```json
{
  "allowedHosts": ["registry.npmjs.org", "npm.mycorp.example"],
  "allowMissingIntegrity": false,
  "allowInstallScripts": ["node-sass", "esbuild"],
  "ignoreRules": ["WG-ENV-ENUM"],
  "failSeverity": "high"
}
```

## Library

```ts
import { scan, snapshot, diff, inventoryOf, meetsFail } from "wormguard";
const { findings } = scan(process.cwd());
if (meetsFail(findings, "high")) process.exit(1);
```

## Status & scope (v1)

npm `package-lock.json` (v1/v2/v3) + `node_modules` script extraction (package-manager-agnostic),
behavioral rules, baseline diff, typosquat, integrity/registry policy, CLI. **Roadmap:** native
pnpm/yarn/bun lockfile parsing, deeper script-file content scanning, signed baselines. Decisions are in
`docs/adr/`; phase acceptance criteria in `docs/PLAN.md`; validation in `VALIDATION.md`.

## License

Source-available — **not** OSI open source. Free under the GNU **AGPL-3.0** for individuals,
non-profits, and organizations below **US$1M annual revenue and 50 employees**; larger organizations
require a commercial license. See [LICENSE](LICENSE).

© 2026 Aris Rhiannon
