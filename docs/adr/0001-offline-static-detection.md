# ADR-0001: Offline static AST analysis + baseline-diff detection

**Status**: Accepted (revised in V1) · **Decider**: Aris Rhiannon

## Context

Lifecycle scripts execute with developer credentials at `npm install` time
and are a recurring vector for supply-chain compromise. Existing free
tools cover adjacent problems: lockfile hygiene, manual sandboxing, CVE
lookup, SaaS behavioral analysis. None offers an offline, deterministic
auditor that performs *real* static analysis of install-time JavaScript.

A precise note on terminology: this project's detection is **static AST
analysis with a small taint approximation, plus indicator-of-compromise
matching, plus baseline diffing**. It is *not* "behavioral" in the
runtime-observation sense (we do not execute the script and observe
side effects). Where the docs use the word "behavioral" it is only to
describe what Socket / Phylum / Aikido do, which is genuinely behavioral
(SaaS pipelines that observe registry-wide install-time behavior). We
intentionally do not claim that label for ourselves.

## Decision

Build the detector around four offline, deterministic layers:

1.  **Real AST analysis** of every JavaScript source invoked by a lifecycle
    script (and inline `node -e "…"` sources) using `acorn` plus a regex
    fallback for unparseable input.

2.  **A bundled IoC corpus** populated from the public GitHub Advisory
    Database (`type=malware&ecosystem=npm`) and refreshable on demand,
    so first-install of a confirmed-malicious package is caught even
    without a baseline.

3.  **A script-fingerprint allowlist** of sha256 hashes of the
    lifecycle-script body strings of widely-used native packages
    (esbuild, sharp, prisma, bcrypt, husky, electron, playwright, …)
    populated from the npm registry packument. A non-matching body on a
    listed package is the explicit worm-injection signature and is
    reported as critical.

4.  **A baseline diff** that flags new lifecycle scripts, integrity
    changes for an unchanged version, registry changes, package set
    changes, and *script body changes for an unchanged version* (the
    canonical worm-injection-on-disk signature) since the snapshot.

## Consequences

- **+** Catches the worm-injection pattern (script-body fingerprint drift)
  on a known package even on first install of the new version.
- **+** Catches confirmed-malicious *new* packages via the IoC corpus
  even on first install with no prior baseline.
- **+** Runs anywhere, including air-gapped CI; nothing is sent off-machine
  during a scan; the scanner is small, auditable, and deterministic.
- **−** Static analysis cannot follow flow-sensitive deobfuscation,
  variable-resolved `require()`, or arbitrary base64 chains beyond one
  level. A targeted attacker who has read this README and the rule
  source can construct a payload that evades the AST analyzer (see
  README §"Limits and bypasses"). This tool is high-leverage against
  *opportunistic* supply-chain attacks (kit-built worm payloads, of
  which the 2025–2026 npm campaigns are typical), not against bespoke
  targeted attacks.
- **−** Does not identify a known-CVE in an unchanged dependency (out
  of scope; pair with `osv-scanner`).
- **−** The IoC corpus and the script-fingerprint allowlist must be
  refreshed periodically to remain useful; the project ships
  `bun run refresh-corpus` and `bun run refresh-allowlist` for this.
