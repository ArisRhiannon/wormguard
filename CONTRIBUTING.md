# Contributing to wormguard

Thanks for helping. wormguard is a deterministic, offline supply-chain
auditor; its usefulness depends almost entirely on the quality of two
human-curated datasets and on honest documentation of what it can and
cannot do. The highest-value contributions are therefore **data with
evidence**, not just code.

Before contributing, read [`docs/adr/0001-offline-static-detection.md`](docs/adr/0001-offline-static-detection.md)
(what the tool is) and [`docs/adr/0002-corpus-and-allowlist-maintenance.md`](docs/adr/0002-corpus-and-allowlist-maintenance.md)
(how the datasets are maintained).

## Ground rules

- **Evidence or it doesn't merge.** Every data change must cite a
  verifiable source (an advisory URL, a registry packument, a reproducible
  command). "Looks fine to me" is not evidence.
- **No marketing in docs.** Claims about detection must be measurable.
  If you change detection, run `bun run scripts/fp-benchmark.ts` and report
  the numbers. Do not reintroduce unmeasured "no false positives" language.
- **Tests stay green.** `bun run check` (typecheck + 216 tests) must pass.
  Detection changes should add a test that fails before and passes after.
- **Never weaken a `critical` to hide a false positive.** Fix the rule's
  precision instead (see the FP baseline for how this was done for
  `WG-IOC-NEAR` and `WG-TYPOSQUAT`).

## Contributing an allowlist fingerprint (`data/script-allowlist.json`)

The allowlist stores sha256 hashes of the **lifecycle-script body strings**
of packages with legitimate install/prepare scripts. A non-matching body on
a listed package is the worm-injection signature (`critical`). Adding a
package here suppresses a benign `WG-INSTALL-SCRIPT` for it, so the bar is
high.

To add a package (e.g. you hit a false `WG-INSTALL-SCRIPT` on `foo`):

1. **Justify legitimacy.** The package must be widely used and its lifecycle
   script must be auditable and benign. Link its source repository and the
   exact script.
2. **Regenerate, don't hand-edit.** Add the name to
   `POPULAR_LIFECYCLE_PACKAGES` in `scripts/populate-allowlist.ts` and run:
   ```sh
   GITHUB_TOKEN=… bun run refresh-allowlist
   ```
   This pulls every published version's lifecycle scripts from the npm
   packument and records each distinct body hash with an audit trail in
   `origins`. Deprecated versions are skipped (we do not fingerprint a
   compromised release).
3. **Paste the evidence in the PR**: the package's weekly downloads, the
   script body you are vouching for, and the `origins` entry produced.
4. **Hash a body string, never a fetched file.** If you find yourself
   wanting to allowlist a hash of a downloaded artifact, stop — that is out
   of scope and unsafe.

A reviewer confirms the package is genuinely popular, the script body is
benign, and the hashes were produced by the script (not pasted by hand).

## Contributing an IoC (`data/iocs.json`)

The corpus is built from the **GitHub Advisory Database**
(`type=malware&ecosystem=npm`) and refreshed automatically (see
`scripts/refresh-corpus.ts` and the `refresh-corpus` workflow). You normally
do **not** hand-edit `data/iocs.json`.

- **A new malware advisory exists in GHSA** → no PR needed; the weekly
  refresh picks it up. To pull it immediately, run `bun run refresh-corpus`
  and open the resulting diff as a PR.
- **An indicator that GHSA does not capture** (a malicious domain, a wallet
  address, a known-malicious script hash) → add it to the `SEED_DOMAINS`,
  `SEED_WALLETS`, or `SEED_SCRIPT_HASHES` arrays in
  `scripts/refresh-corpus.ts`, with a comment linking the advisory/report
  it came from, then run the refresh. These seeds are merged into the
  corpus on every refresh.

Every IoC seed **must** cite a public source (GHSA, Socket, Aikido, a vendor
write-up, or a first-party incident report). Indicators without a citation
are rejected.

## The manual part we do NOT automate (and why)

New-campaign indicators routinely appear in human-written security research
(Socket, Aikido, StepSecurity, GitHub Security Lab, vendor blogs) **days
before** they land in a structured feed like GHSA. Reading that research,
judging credibility, and extracting the durable indicators is a human task —
it requires editorial judgement that we deliberately do not hand to a
scraper (a scraper would ingest unvetted, possibly attacker-planted text).

The standing process (see ADR-0002):

1. **Cadence**: a maintainer reviews the major npm-supply-chain research
   sources roughly weekly (more often during an active campaign).
2. **Extract** only durable, verifiable indicators: package
   name+version ranges (prefer letting GHSA carry these), C2 domains,
   wallet addresses, malicious script hashes.
3. **Encode** them as cited seeds in `scripts/refresh-corpus.ts` (per
   above) and open a PR with the source links.
4. **Review**: a second person confirms each indicator against its cited
   source before merge.

This is the one part of wormguard that does not scale by code, on purpose.
If you do this curation, your PR is exactly as valuable as a code PR.

## Submitting changes

- Branch, commit with a clear message, open a PR against `main`.
- CI (typecheck + tests on Linux/macOS, CLI smoke, corpus-integrity) must be
  green. `main` is protected.
- For detection changes, include before/after `fp-benchmark` numbers and a
  test.
