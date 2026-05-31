# ADR-0001: Offline behavioral + baseline-diff detection (no CVE database)

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
The dominant npm threat in 2025–2026 is self-propagating worms (Shai-Hulud / Mini Shai-Hulud) that
inject malicious lifecycle scripts into *new versions of trusted packages* to steal CI/CD secrets.
CVE/OSV scanners only match *known* bad versions and therefore lag zero-days; SaaS scanners require
network access and accounts.

## Decision
Detect compromise **behaviorally** (what lifecycle scripts do) and **differentially** (what changed
versus a committed baseline), entirely **offline**, with **no vulnerability database** and **no network
or telemetry**. The highest-signal detector is the baseline diff: a package that *gains* an install
script, or whose integrity/registry changes for the same version, is flagged immediately.

## Consequences
- **+** Catches zero-day supply-chain attacks the moment they change the tree — no DB to update.
- **+** Runs anywhere, including air-gapped CI; nothing is sent off-machine; trivially auditable.
- **−** Cannot identify a *known-CVE* in an unchanged, already-malicious dependency (out of scope; pair
  with an OSV scanner for that axis).
- **−** Heuristics can be evaded; positioned as defense-in-depth / early warning, not a guarantee.
