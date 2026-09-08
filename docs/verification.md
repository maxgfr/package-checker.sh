# Functional and performance verification — 2026-09-08

This review preserves the CLI, export schemas and scanner runtime dependencies.
Source files are authoritative; `script.sh` is regenerated with `build.sh`.

## Corrections

- Preserve separate GHSA/CVE advisories sharing a version or range, including
  across sources. Deduplicate repeated advisories without dropping distinct ones.
- Remove the global patched-version cutoff that could hide a matching interval
  after loading another source. Preserve whole OR expressions through parsing.
- Correct numeric prerelease ordering and ignore build metadata for ordering.
  Share the tested semver comparison between npm-family consumers and Go.
  Keep the legacy conservative npm prerelease policy out of Go and other
  ecosystems; split OR branches before expanding caret/tilde shorthand and
  compare unbounded numeric identifiers without shell integer overflow.
- Escape all JSON/CSV export fields, count an empty export as zero and honor
  optional export filenames. The public schema still projects the first matching
  advisory per occurrence; full advisory lists remain in console/issue reports.
- Load configuration before discovery/GitHub fetching, apply dependency filters
  correctly to compact manifests, and fix numeric CSV column selection and
  caret/tilde/wildcard CSV range detection.
- Diagnose missing option values, missing explicit configuration and malformed
  source/config/project JSON. JSON validation accepts nesting up to 128 levels.
- Parse npm v1 transitive dependencies, npm aliases, pnpm legacy/peer resolution
  keys and Hex package identities independently of local application names.
  Support compact JSON for npm, Composer, NuGet, Swift and Pipfile lockfiles.
  Join requirements.txt continuation lines before extracting hashed pins.
- Reject unsuccessful/truncated HTTP downloads, propagate GitHub failures, reject
  truncated repository trees, and check the HTTP status when creating an issue.
- Generate every disjoint vulnerability interval, exclude withdrawn advisories,
  and preserve previous feed files when cloning, downloading or parsing fails.
  Preserve OSV limit bounds and the union of explicit versions and ranges.
  An explicit empty `fixed=` PURL parameter prevents a limit-only bound from
  being misreported as a known patched release.
- Restore piped execution while keeping sourcing side-effect-free with respect
  to running `main`; diagnose unsupported Bash 3 explicitly.

## Coverage

| Area | Verification |
| --- | --- |
| npm, Yarn Classic/Berry, pnpm, Bun, Deno, shrinkwrap | Existing fixtures plus isolated lockfile scans and manifest filters |
| Python, Go, Rust, Ruby, PHP, Maven/Gradle, NuGet, Dart, Hex, Swift, Actions | Every registered filename/path dispatcher, expected package and ecosystem |
| Versions | Existing 156 comparator assertions plus build, prerelease, disjoint and OR regressions |
| Sources | JSON, CSV, PURL, SARIF, CycloneDX, Trivy; columns, multiple sources, malformed JSON |
| Configuration/CLI | Exclusions, dependency types, default feeds, ecosystem override, help, lookup, invalid combinations, piped execution |
| Reports | JSON/CSV round trips, control characters, empty count, write failure, duplicate/distinct advisories |
| Network | Local HTTP redirect/error/partial responses; mocked GitHub pagination, rate limits, tree download and issue payload/status |
| Feed generation | Canonicalization, separation, disjoint/reintroduced intervals, withdrawn advisories, worker failures and preservation of existing files |
| Runtime/portability | No jq/Python/Node on the scan path; Bash 3 rejection; OS/awk matrix and shipped Docker images |

The historical launcher contains 40 scenario groups (which include the original
bug, metadata and version suites), plus six original feed-generation assertions.
The Python suite also checks positive and negative cases independently of those
fixtures, including equivalent JSON representations, nested metadata, stale
legacy lockfile sections, aliases, peer resolutions and malformed project input.

The final suite passes all 40 historical scenario groups, the six original feed
assertions and 76 Python test methods on macOS/system awk, macOS/gawk,
Ubuntu 24.04/gawk and Ubuntu 24.04/mawk. The Linux checks ran in local arm64
containers. Docker lite, full/npm and full/all images build and pass vulnerable
and clean scans, no-jq checks and bundled-feed checks.

The independent validator was started with no conversation history and derived
new test cases from the repository documentation and upstream formats. Its eleven
test methods are in `tests/test_independent.py`; the parent integrated the
malformed-input fix and regenerated the distributable. Eight golden hashes lock
down structural JSON output around Unicode/escape chunk boundaries. Another
147 generated JSON inputs are checked against Python standard-parser verdicts.

Semantic references used for expected behavior:
[pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/),
[Go semver](https://pkg.go.dev/golang.org/x/mod/semver),
[OSV evaluation algorithm](https://ossf.github.io/osv-schema/#evaluation),
[npm lockfiles](https://docs.npmjs.com/cli/v7/configuring-npm/package-lock-json),
[pnpm lockfile specification](https://github.com/pnpm/spec/tree/master/lockfile),
and [Hex package publishing](https://hex.pm/docs/publish).

## Performance

The final comparison uses one warmup plus seven timed runs per case on macOS
arm64 with Bash 5.3.15 and system awk, alternating old/new order. The baseline is
commit `0b8f749`. Raw results are in [benchmark-results.json](../tests/benchmark-results.json).

| Scenario | Before, median | After, median | Median paired speedup | Peak RSS before → after |
| --- | ---: | ---: | ---: | ---: |
| Small npm project | 0.219 s | 0.140 s | 1.44× | 9.2 → 10.4 MiB |
| Polyglot project | 0.083 s | 0.075 s | 1.11× | 9.3 → 9.1 MiB |
| Large feed | 0.674 s | 0.272 s | 2.53× | 28.6 → 17.1 MiB |
| 100-package monorepo | 3.385 s | 1.350 s | 2.62× | 29.3 → 16.6 MiB |
| 5,000-dependency lockfile | 0.496 s | 0.379 s | 1.28× | 29.0 → 16.5 MiB |

The machine had unrelated CPU load and concurrent validation. Small-case timings
remain sensitive to this load. Peak memory falls roughly 40–43% for the three
large cases; the small npm case adds about 1.2 MiB for more complete parsing.
Absolute timings should be remeasured on an idle machine before setting a
performance gate. No latency regression was observed in this final paired run;
that is evidence for these scenarios, not a universal performance guarantee.

The validation work itself initially introduced a measured JSON performance
regression. Profiling isolated whole-document character indexing, compact-line
indexing and empty advisory work for unlisted packages. Bounded JSON processing,
simple-token fast paths and early negative lookup return removed those costs
without disabling input validation or changing golden parser outputs.

The benchmark reports the same package occurrences before and after. For the
large feed, the two `next@16.0.3` export rows now contain the first matching
GHSA-mwv6-3258-q52c/high advisory instead of GHSA-w37m-7fhw-fmv9/moderate: this is
the metadata-collision correction, not a change to detected occurrences. Other
benchmark reports are identical after canonicalization.

## Limits and follow-up validation

- Hosted CI is separate from the local container matrix; final results must be
  checked on the pushed commit. The modified test workflow passes actionlint.
- Local Docker initially returned engine errors and then reused a corrupted
  Alpine cache entry containing zero-byte executables. An isolated builder and
  deletion of that exact test-created cache entry restored all three image tests;
  no preexisting containers or unrelated caches were deleted.
- GitHub/OSV production services and real issue creation are not exercised by
  offline tests. All writes in integration tests target temporary directories or
  mocked services.
- Committed vulnerability datasets have not been refreshed. The corrected
  generator will affect them on the next successful feed-generation run.
- Existing documented parsing limitations remain: unresolved Maven properties,
  non-pinned requirements/includes and remote workflow
  discovery. Synthetic uv/pdm tests verify shared TOML parsing and dispatch, not
  every upstream lockfile version. Paths containing newlines or the internal `|`
  separator are not covered by this review.
- Passing this suite guards the exercised behavior; it is not a proof that all
  possible inputs or upstream format changes are regression-free.
