# ADR-0002: Industry-standard dependencies (the "zero-dep" stance was vanity)

**Status**: Accepted (supersedes the original "zero-dep" ADR) · **Decider**: Aris Rhiannon

## Context

The original v0 implementation tried to parse `package-lock.json` v1/v2/v3
by hand, with the goal of having no runtime dependencies. This stance
was self-defeating: lockfile formats evolve (pnpm v6→v7→v9, yarn classic
vs berry, bun.lock JSONC), edge cases proliferate (workspaces, peer
deps, registry overrides), and the pursuit of zero-deps was driving us
toward a parser zoo we'd be debugging instead of improving the actual
detection logic. The same applies to JavaScript AST parsing and to
cryptography: rolling our own would be both slower and less safe than
delegating to maintained libraries authored by the ecosystem itself.

## Decision

Adopt a small, audited set of dependencies, all from official ecosystem
maintainers:

- `acorn` + `acorn-walk` — the JavaScript parser used by webpack, rollup,
  ESLint. Permits ECMAScript 2024, location tracking, and module/script
  fallback. Tiny, dependency-free.
- `shell-quote` — the shell tokenizer used by webpack, vercel, etc.
  We need this to correctly parse lifecycle commands across `&&`, `||`,
  `;`, `|` operators without losing the quoting of inline `node -e "…"`.
- `@yarnpkg/lockfile` — the official yarn classic lockfile parser.
- `yaml` — the standard JS YAML parser; used for pnpm and yarn berry
  lockfiles.
- `ssri` — the official npm Subresource Integrity verifier.
- `sigstore` — the official sigstore-js library; ships its own bundled
  trust roots (Fulcio CA, Rekor public key, CT log keys) via TUF, and
  performs the cryptography offline. We never roll our own crypto.

## Consequences

- **+** Lockfile parsing is now correct across npm v1/v2/v3, pnpm v6/v7/v9,
  yarn classic, yarn berry, and bun.lock — by reusing the same code the
  package managers themselves ship.
- **+** AST analysis is real, not regex pattern matching.
- **+** Cryptographic verification of sigstore bundles is delegated to
  the same library npm uses for `npm publish --provenance`.
- **−** Larger install footprint (~99 transitive packages at devtime,
  much of which is dev-only TypeScript types). The total runtime
  dependency tree is small and audit-tractable; we accept the trade.
- **−** We now have a supply-chain dependency on these packages. We
  reduce the risk by pinning to specific minor versions in
  `package.json` and by including the dependency review in our own CI.
