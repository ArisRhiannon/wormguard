# ADR-0002: Zero-dependency heuristics, severity tiers & false-positive control

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
A security tool people will actually run in CI must be tiny, auditable, and low-noise. Pulling in a JS
parser, YAML library, or a remote feed would add attack surface and friction — ironic for a
supply-chain tool.

## Decision
- **Zero runtime dependencies.** Parse `package-lock.json` with `JSON.parse`; read lifecycle scripts
  from `node_modules/*/package.json`; analyze script **command strings** with a small, reviewable
  regex rule set (no JS AST parser). Bundle the typosquat reference list as a TS array.
- **Severity tiers** (`critical|high|medium|low`) with a configurable `failSeverity` (default `high`),
  so CI only fails on meaningful signal and `low` advisories stay quiet.
- **False-positive control**: benign build scripts (`tsc -b`, `node-gyp rebuild`) yield at most a `low`
  advisory; an allowlist (`allowInstallScripts`, `allowedHosts`, `ignoreRules`) suppresses known-good
  cases; the high-signal `WG-DIFF-NEW-SCRIPT` is preferred over blanket "has a script" alarms.

## Consequences
- **+** Tiny, fast, auditable; no supply-chain risk from wormguard itself.
- **+** Tunable noise floor fits real CI pipelines.
- **−** Regex heuristics on command strings can miss heavily obfuscated payloads or over-match unusual
  but benign scripts; mitigated by severity tiers, the allowlist, and the diff-first philosophy.
- **−** npm-lockfile-first; pnpm/yarn/bun metadata parsing is roadmap (their *scripts* are already
  covered by the package-manager-agnostic `node_modules` scan).
