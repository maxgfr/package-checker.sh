#!/usr/bin/env bash
# Network-free unit test for the feed-generation jq emission (FEED_JQ_PROGRAM).
# Feeds canned OSV/GHSA advisory blobs through the exact jq program used by
# fetch_osv/fetch_ghsa and asserts the emitted PURL line, focusing on the
# per-ecosystem name canonicalization that MUST match canon_purl_name in the
# scan-side parser (maven colon->slash, PEP503 pypi, swift URL stripping,
# githubactions lowercasing, npm identity, and cross-ecosystem filtering).
#
# Not wired into CI (requires jq, a fetch-path-only dependency). Run manually:
#   bash test-fixtures/test-feed-generation.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/script.sh"   # sourced: main() not run (run guard); loads FEED_JQ_PROGRAM

if ! command -v jq >/dev/null 2>&1; then
    echo "⏭️  jq not installed — skipping feed-generation jq test"
    exit 0
fi

PASS=0
FAIL=0

# assert <name> <source> <ecomap-json> <advisory-json> <expected-line>
assert_emit() {
    local name="$1" src="$2" ecomap="$3" blob="$4" expected="$5"
    local got
    got=$(printf '%s' "$blob" | jq -r --arg source "$src" --argjson ecomap "$ecomap" "$FEED_JQ_PROGRAM" 2>/dev/null)
    if [ "$got" = "$expected" ]; then
        echo "  ✅ $name"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name"
        echo "     expected: $expected"
        echo "     got:      $got"
        FAIL=$((FAIL + 1))
    fi
}

MAP='{"Maven":"maven","PyPI":"pypi","SwiftURL":"swift","GitHub Actions":"githubactions","npm":"npm","Go":"golang"}'

echo "=========================================="
echo "Feed generation jq emission tests"
echo "=========================================="

# maven: groupId:artifactId -> pkg:maven/groupId/artifactId (colon becomes slash)
assert_emit "maven colon->slash" "osv" "$MAP" \
'{"id":"GHSA-mvn","aliases":["GHSA-mvn","CVE-2021-0001"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Maven","name":"org.springframework:spring-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.3.20"}]}]}]}' \
'pkg:maven/org.springframework/spring-core@>=0 <5.3.20?severity=high&ghsa=GHSA-mvn&cve=CVE-2021-0001&source=osv'

# pypi: PEP 503 normalization (lowercase; runs of . _ - collapse to a single -)
assert_emit "pypi PEP503 normalize" "osv" "$MAP" \
'{"id":"PYSEC-1","aliases":["CVE-2021-0002"],"database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"PyPI","name":"Django_REST.framework"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.11.0"}]}]}]}' \
'pkg:pypi/django-rest-framework@>=0 <3.11.0?severity=moderate&cve=CVE-2021-0002&source=osv'

# swift: strip scheme + trailing .git, lowercase
assert_emit "swift URL/.git strip" "osv" "$MAP" \
'{"id":"GHSA-sw","aliases":["GHSA-sw"],"database_specific":{"severity":"LOW"},"affected":[{"package":{"ecosystem":"SwiftURL","name":"https://github.com/Apple/Swift-NIO.git"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}' \
'pkg:swift/github.com/apple/swift-nio@>=0 <2.0.0?severity=low&ghsa=GHSA-sw&source=osv'

# githubactions: lowercase owner/repo; introduced+last_affected -> >= <=
assert_emit "githubactions lowercase" "osv" "$MAP" \
'{"id":"GHSA-gh","aliases":[],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"GitHub Actions","name":"Actions/Checkout"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"3.0.0"}]}]}]}' \
'pkg:githubactions/actions/checkout@>=1.0.0 <=3.0.0?severity=high&source=osv'

# npm identity + GHSA id-from-.id + no-range MAL-style exact version emission
assert_emit "npm identity (ghsa, exact ver)" "ghsa" "$MAP" \
'{"id":"GHSA-npm-mal","aliases":[],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"npm","name":"@scope/evil"},"versions":["1.0.0"]}]}' \
'pkg:npm/@scope/evil@1.0.0?severity=critical&ghsa=GHSA-npm-mal&source=ghsa'

# cross-ecosystem advisory + single-entry ecomap: only the mapped ecosystem emits
# (GHSA id comes from .id under source=ghsa, so ghsa=GHSA-x is expected)
assert_emit "cross-eco filter (npm only)" "ghsa" '{"npm":"npm"}' \
'{"id":"GHSA-x","aliases":[],"affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]},{"package":{"ecosystem":"PyPI","name":"b"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}' \
'pkg:npm/a@>=0 <1.0.0?severity=unknown&ghsa=GHSA-x&source=ghsa'

echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="
[ "$FAIL" -eq 0 ]
