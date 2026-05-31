# False-positive baseline

This document records the **measured** false-positive (FP) rate of `wormguard
scan` against a tree of known-clean, widely-used packages, the root causes of
the false positives found, the fixes applied, and how to reproduce the
measurement. It exists because the project previously claimed "no false
positives" without evidence; that claim was **refuted** by the first real
measurement and has been replaced with the numbers below.

Reproduce with:

```sh
bun run scripts/fp-benchmark.ts            # installs the pinned set, scans
bun run scripts/fp-benchmark.ts /some/tree # or scan an existing node_modules tree
```

## Method

- **Tree**: a `package.json` with 20 direct dependencies (`react`, `react-dom`,
  `express`, `lodash`, `axios`, `chalk`, `vue`, `vite`, `esbuild`, `typescript`,
  `webpack`, `eslint`, `prettier`, `jest`, `better-sqlite3`, `bcrypt`, `husky`,
  `prisma`, `@swc/core`, `nodemon`), installed with
  `npm install --ignore-scripts`, resolving to **~662 packages** in the full
  transitive tree.
- The set is intentionally heavy on packages with **legitimate lifecycle
  scripts** (esbuild, sharp via transitive, prisma, better-sqlite3, bcrypt,
  husky, @swc/core) — the hardest FP cases.
- Every package in the tree is legitimate, so **any `critical`/`high` finding is
  a false positive** — the kind that breaks CI and erodes trust. `medium`/`low`
  are treated as informational (non-gating).

## Result

| Severity            | Before | After |
|---------------------|-------:|------:|
| critical            |      0 |     0 |
| **high**            | **14** | **0** |
| medium              |      6 |     2 |
| low (informational) |   ~661 |  ~661 |

**CI-gating false positives (critical+high): 14 → 0.**

The low tier is dominated by `WG-PROVENANCE-MISSING` (≈616 — most packages on
npm still ship without a provenance attestation) and `WG-INSTALL-SCRIPT` (≈38 —
correctly noting that a package *has* a lifecycle script; a true observation,
not a FP). These are informational and never gate CI.

## Root causes of the 14 high + 6 medium false positives

1. **`TOP_NAMES` was only 500 entries.** Ubiquitous packages — `cookie`, `ini`,
   `rc`, `source-map`, `etag`, `browserslist`, `base64-js`, `levn`,
   `path-exists`, `follow-redirects`, `nypm`, `pathe` — were not recognised as
   legitimate, so both the typosquat and IoC-near rules fired on them.
2. **`WG-IOC-NEAR` is structurally prone to FPs.** The malware corpus is
   dominated by *typosquats of popular packages* (`acookie`→`cookie`,
   `suorce-map`→`source-map`, `colors-support`→`color-support`). A legitimate
   popular package is therefore, by construction, edit-distance-1 from its own
   malicious typosquat. Firing `high` on the legitimate target is exactly
   backwards.
3. **The distance-2 typosquat tier was pure noise.** On this tree it produced
   only false positives (`effect`~`expect`, `esquery`~`jquery`,
   `exsolve`~`resolve`, `@vue/compiler-ssr`~`@vue/compiler-sfc`) and zero true
   positives. Real typosquats are overwhelmingly single-edit.

## Fixes applied

- **Expanded `TOP_NAMES` 500 → ~5,075** (`scripts/refresh-top-names.ts`, now
  configurable + rate-limit-resilient). Any scanned name present here is
  recognised as legitimate and skipped by both rules.
- **`WG-TYPOSQUAT`: scan path uses `maxDist=1`** (the library function still
  supports `maxDist=2` for explicit callers). Removes the distance-2 noise.
- **`WG-TYPOSQUAT`: target-length floor.** Ultra-short popular targets (`npm`,
  `ms`, `fs`, `rc`) have dense distance-1 neighbourhoods of legitimate packages
  and are rarely real typosquat targets; they are skipped. Kills `nypm`←`npm`.
- **`WG-IOC-NEAR`: severity `high` → `medium`.** It is a fuzzy *proximity*
  heuristic, not a confirmed indicator. The exact match (`WG-IOC-NAME`) remains
  `critical`. This stops the rule from gating CI on a guess.
- **`WG-IOC-NEAR`: length floor (≥5 chars).** Short names collide densely in a
  23k-name corpus; the exact matcher still covers them.

Real-attack detection was re-verified intact after the fixes: `expresss` →
`WG-TYPOSQUAT` **high**; a `curl … | sh` postinstall → `WG-SHELL-PIPE`
**critical**; exit code `1` under `--ci`. All 216 tests pass.

## Residual findings (honest caveats)

The "after" tree still produces **2 medium** findings. Neither gates CI, and
both are defensible, but they are not zero:

- `WG-IOC-NEAR color-support` — `color-support` is a legitimate package that is
  genuinely one edit from the real malware `colors-support`. It is **not** in
  the top ~5,075, so it isn't auto-recognised. Reported as `medium`
  (informational) rather than suppressed.
- `WG-AST-FS-WRITE mime` — `mime@1.6.0` ships `"prepare": "node src/build.js"`,
  and that script really does call `fs.writeFileSync`. This is a *true*
  detection of a filesystem write in a lifecycle-referenced script. (Note:
  `prepare` does not run for packages installed from the registry tarball, only
  for git/local installs — so the real-world impact is low. The static
  detection is nonetheless correct.)

**This is one tree, not a universe.** The measured 0% critical/high FP rate
applies to this specific popular-package set. A different tree — especially one
with many mid-popularity packages outside the top ~5,075 — can still surface
`medium` `WG-IOC-NEAR` findings. The honest claim is therefore: *zero CI-gating
false positives on a representative tree of 662 popular packages*, **not**
"no false positives ever." Re-run `scripts/fp-benchmark.ts` against your own
tree to measure your environment.
