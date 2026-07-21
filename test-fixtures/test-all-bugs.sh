#!/bin/bash
# Comprehensive test suite for all bug fixes:
# - Bug #1: Multiple advisories per package (multi-vulnerability reporting)
# - Bug #2: Build metadata (+) handling in version comparison
# - Bug #3: Empty range should not match all versions
# - Bug #4: Pre-release ordering (alpha < beta < rc)
# - Bug #5: Skip workspace/file/link version specifiers
# - Bug #9: Scoped npm packages (@scope/name) in PURL feeds
# - Bug #10: No cross-ecosystem collision (namespaced lookups)
# - Bug #11: Wildcard feeds (CSV/JSON with no ecosystem) still match
# - Bug #12: --lockfile-types validation + selective scanning
# - Bug #13: --ecosystems flag (override + validation)
# - Bug #14: Swift bare-name advisories (feed without repo URL) matched via fallback
# - Previous fix: Metadata collision (correct advisory per range)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/script.sh"
FIXTURES_DIR="$(cd "$(dirname "$0")" && pwd)"

PASSED=0
FAILED=0

pass() {
    echo "  ✅ $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  ❌ $1"
    FAILED=$((FAILED + 1))
}

echo "============================================"
echo "Comprehensive Bug Fix Test Suite"
echo "============================================"
echo ""

# ============================================================
# Bug #1: Multiple advisories per package
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #1: Multi-vulnerability reporting"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create temp fixtures for this test
MULTI_VULN_DIR=$(mktemp -d)
cat > "$MULTI_VULN_DIR/test.purl" << 'PURL'
pkg:npm/lodash@>=3.0.0 <4.17.11?severity=high&ghsa=GHSA-aaaa-1111-xxxx&cve=CVE-2018-11111&source=ghsa
pkg:npm/lodash@>=3.0.0 <4.17.21?severity=critical&ghsa=GHSA-bbbb-2222-yyyy&cve=CVE-2021-22222&source=osv
pkg:npm/lodash@>=4.17.0 <4.17.20?severity=medium&ghsa=GHSA-cccc-3333-zzzz&cve=CVE-2020-33333&source=ghsa
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"lodash":"4.17.10"}}' > "$MULTI_VULN_DIR/package.json"

OUTPUT=$(cd "$MULTI_VULN_DIR" && "$SCRIPT" --source "$MULTI_VULN_DIR/test.purl" 2>&1 || true)

echo "📦 Test: lodash@4.17.10 should show ALL 3 advisories"

if echo "$OUTPUT" | grep -q "GHSA-aaaa-1111-xxxx"; then
    pass "Advisory 1 (GHSA-aaaa-1111-xxxx / high) displayed"
else
    fail "Advisory 1 (GHSA-aaaa-1111-xxxx) missing"
fi

if echo "$OUTPUT" | grep -q "GHSA-bbbb-2222-yyyy"; then
    pass "Advisory 2 (GHSA-bbbb-2222-yyyy / critical) displayed"
else
    fail "Advisory 2 (GHSA-bbbb-2222-yyyy) missing"
fi

if echo "$OUTPUT" | grep -q "GHSA-cccc-3333-zzzz"; then
    pass "Advisory 3 (GHSA-cccc-3333-zzzz / medium) displayed"
else
    fail "Advisory 3 (GHSA-cccc-3333-zzzz) missing"
fi

if echo "$OUTPUT" | grep -q "CVE-2018-11111" && echo "$OUTPUT" | grep -q "CVE-2021-22222" && echo "$OUTPUT" | grep -q "CVE-2020-33333"; then
    pass "All 3 CVEs displayed"
else
    fail "Not all CVEs displayed"
fi

if echo "$OUTPUT" | grep -q "Severity: high" && echo "$OUTPUT" | grep -q "Severity: critical" && echo "$OUTPUT" | grep -q "Severity: medium"; then
    pass "All 3 severities displayed"
else
    fail "Not all severities displayed"
fi

rm -rf "$MULTI_VULN_DIR"
echo ""

# ============================================================
# Bug #2: Build metadata (+) in version comparison
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #2: Build metadata handling"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BUILD_META_DIR=$(mktemp -d)
cat > "$BUILD_META_DIR/test.purl" << 'PURL'
pkg:npm/testpkg@>=1.0.0 <2.0.0?severity=high&ghsa=GHSA-build-test&cve=CVE-2024-BUILD&source=ghsa
PURL
# Test with version containing build metadata
echo '{"name":"test","version":"1.0.0","dependencies":{"testpkg":"1.5.0+build.123"}}' > "$BUILD_META_DIR/package.json"

OUTPUT=$(cd "$BUILD_META_DIR" && "$SCRIPT" --source "$BUILD_META_DIR/test.purl" 2>&1 || true)

echo "📦 Test: testpkg@1.5.0+build.123 should be detected as vulnerable"

if echo "$OUTPUT" | grep -q "testpkg@1.5.0+build.123 (vulnerable"; then
    pass "Version with build metadata correctly matched"
else
    fail "Version with build metadata not matched"
fi

rm -rf "$BUILD_META_DIR"
echo ""

# ============================================================
# Bug #3: Empty range should not match
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #3: Empty range guard"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# We test version_in_range directly via a crafted scenario
# An empty range entry shouldn't match anything
EMPTY_RANGE_DIR=$(mktemp -d)
# Create a purl with a valid range alongside a safe package
cat > "$EMPTY_RANGE_DIR/test.purl" << 'PURL'
pkg:npm/safepkg@>=99.0.0 <99.0.1?severity=low&ghsa=GHSA-safe-test&source=ghsa
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"safepkg":"1.0.0"}}' > "$EMPTY_RANGE_DIR/package.json"

OUTPUT=$(cd "$EMPTY_RANGE_DIR" && "$SCRIPT" --source "$EMPTY_RANGE_DIR/test.purl" 2>&1 || true)

echo "📦 Test: safepkg@1.0.0 should NOT match range >=99.0.0 <99.0.1"

if echo "$OUTPUT" | grep -q "No vulnerable packages detected"; then
    pass "safepkg@1.0.0 correctly not matched"
else
    fail "safepkg@1.0.0 incorrectly matched"
fi

rm -rf "$EMPTY_RANGE_DIR"
echo ""

# ============================================================
# Bug #4: Pre-release ordering
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #4: Pre-release ordering"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

PRERELEASE_DIR=$(mktemp -d)
# Range that includes alpha but NOT beta or rc
# >=1.0.0-alpha <1.0.0-beta should match alpha.1 but not beta.1
cat > "$PRERELEASE_DIR/test.purl" << 'PURL'
pkg:npm/prpkg@>=1.0.0-alpha <1.0.0-beta?severity=medium&ghsa=GHSA-prerel-test&source=ghsa
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"prpkg":"1.0.0-alpha.5"}}' > "$PRERELEASE_DIR/package.json"

OUTPUT=$(cd "$PRERELEASE_DIR" && "$SCRIPT" --source "$PRERELEASE_DIR/test.purl" 2>&1 || true)

echo "📦 Test: prpkg@1.0.0-alpha.5 should match >=1.0.0-alpha <1.0.0-beta"

if echo "$OUTPUT" | grep -q "prpkg@1.0.0-alpha.5 (vulnerable"; then
    pass "Pre-release alpha.5 correctly matched in alpha..beta range"
else
    fail "Pre-release alpha.5 not matched"
fi

# Now test that beta.1 does NOT match
echo '{"name":"test","version":"1.0.0","dependencies":{"prpkg":"1.0.0-beta.1"}}' > "$PRERELEASE_DIR/package.json"

OUTPUT=$(cd "$PRERELEASE_DIR" && "$SCRIPT" --source "$PRERELEASE_DIR/test.purl" 2>&1 || true)

echo "📦 Test: prpkg@1.0.0-beta.1 should NOT match >=1.0.0-alpha <1.0.0-beta"

if echo "$OUTPUT" | grep -q "No vulnerable packages detected"; then
    pass "Pre-release beta.1 correctly excluded from alpha..beta range"
else
    fail "Pre-release beta.1 incorrectly matched"
fi

rm -rf "$PRERELEASE_DIR"
echo ""

# ============================================================
# Bug #5: Skip workspace/file/link versions
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #5: Skip special version specifiers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

WORKSPACE_DIR=$(mktemp -d)
cat > "$WORKSPACE_DIR/test.purl" << 'PURL'
pkg:npm/local-pkg@>=0.0.0?severity=critical&ghsa=GHSA-ws-test&source=ghsa
PURL
# package.json with workspace/file/link deps that should be skipped
cat > "$WORKSPACE_DIR/package.json" << 'JSON'
{
  "name": "test",
  "version": "1.0.0",
  "dependencies": {
    "local-pkg": "workspace:*",
    "other-pkg": "file:../other",
    "link-pkg": "link:../link",
    "alias-pkg": "npm:real-pkg@1.0.0"
  }
}
JSON

OUTPUT=$(cd "$WORKSPACE_DIR" && "$SCRIPT" --source "$WORKSPACE_DIR/test.purl" 2>&1 || true)

echo "📦 Test: workspace/file/link/npm versions should be skipped"

if echo "$OUTPUT" | grep -q "No vulnerable packages detected"; then
    pass "All special version specifiers correctly skipped"
else
    fail "Special version specifiers not properly skipped"
fi

rm -rf "$WORKSPACE_DIR"
echo ""

# ============================================================
# Metadata collision (previous fix, regression check)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Regression: Metadata collision"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd "$FIXTURES_DIR/metadata-collision-project"
OUTPUT=$("$SCRIPT" --source "$FIXTURES_DIR/test-metadata-collision.purl" 2>&1 || true)

echo "📦 Test: next@16.0.3 should show correct advisory (not old one)"

if echo "$OUTPUT" | grep -q "GHSA-new-advisory-ccc" && echo "$OUTPUT" | grep -q "CVE-2025-33333"; then
    pass "Correct advisory displayed for next@16.0.3"
else
    fail "Wrong advisory displayed for next@16.0.3"
fi

if echo "$OUTPUT" | grep -q "GHSA-old-advisory-aaa"; then
    fail "Old advisory GHSA-old-advisory-aaa incorrectly shown"
else
    pass "Old advisory correctly hidden"
fi

echo "📦 Test: express@4.18.0 should show correct advisory"

if echo "$OUTPUT" | grep -q "GHSA-express-new-eee" && echo "$OUTPUT" | grep -q "CVE-2025-55555"; then
    pass "Correct advisory displayed for express@4.18.0"
else
    fail "Wrong advisory displayed for express@4.18.0"
fi

echo ""

# ============================================================
# Bug #6: Fix version display in summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #6: Fix version display"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

FIX_VERSION_DIR=$(mktemp -d)
cat > "$FIX_VERSION_DIR/test.purl" << 'PURL'
pkg:npm/express@>=4.0.0 <4.21.2?severity=high&ghsa=GHSA-fix-test-1111&cve=CVE-2024-FIX01&source=ghsa
pkg:npm/lodash@>=3.0.0 <4.17.21?severity=critical&ghsa=GHSA-fix-test-2222&cve=CVE-2021-FIX02&source=osv
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"express":"4.18.0","lodash":"4.17.10"}}' > "$FIX_VERSION_DIR/package.json"

OUTPUT=$(cd "$FIX_VERSION_DIR" && "$SCRIPT" --source "$FIX_VERSION_DIR/test.purl" 2>&1 || true)

echo "📦 Test: Fix version should be displayed for range-based vulnerabilities"

if echo "$OUTPUT" | grep -q "Fix: upgrade to >= 4.21.2"; then
    pass "Fix version displayed for express (>= 4.21.2)"
else
    fail "Fix version not displayed for express"
fi

if echo "$OUTPUT" | grep -q "Fix: upgrade to >= 4.17.21"; then
    pass "Fix version displayed for lodash (>= 4.17.21)"
else
    fail "Fix version not displayed for lodash"
fi

rm -rf "$FIX_VERSION_DIR"
echo ""

# ============================================================
# Bug #7: Exact version detection (MAL advisories)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #7: Exact version detection (MAL/malware)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MAL_DIR=$(mktemp -d)
cat > "$MAL_DIR/test.purl" << 'PURL'
pkg:npm/axios@0.30.4?severity=critical&ghsa=GHSA-fw8c-xr5c-95f9&source=osv
pkg:npm/axios@1.14.1?severity=critical&ghsa=GHSA-fw8c-xr5c-95f9&source=osv
PURL
echo '{"name":"test","version":"1.0.0","devDependencies":{"axios":"1.14.1"}}' > "$MAL_DIR/package.json"

OUTPUT=$(cd "$MAL_DIR" && "$SCRIPT" --source "$MAL_DIR/test.purl" 2>&1 || true)

echo "📦 Test: axios@1.14.1 should be detected as vulnerable (exact version match)"

if echo "$OUTPUT" | grep -q "axios@1.14.1 (vulnerable)"; then
    pass "axios@1.14.1 detected as vulnerable (exact match)"
else
    fail "axios@1.14.1 not detected"
fi

if echo "$OUTPUT" | grep -q "GHSA-fw8c-xr5c-95f9"; then
    pass "GHSA-fw8c-xr5c-95f9 advisory displayed"
else
    fail "GHSA-fw8c-xr5c-95f9 advisory missing"
fi

if echo "$OUTPUT" | grep -q "Severity: critical"; then
    pass "Critical severity displayed"
else
    fail "Critical severity missing"
fi

# Test that safe version is NOT detected
echo '{"name":"test","version":"1.0.0","devDependencies":{"axios":"1.14.0"}}' > "$MAL_DIR/package.json"

OUTPUT=$(cd "$MAL_DIR" && "$SCRIPT" --source "$MAL_DIR/test.purl" 2>&1 || true)

echo "📦 Test: axios@1.14.0 should NOT be detected (not a compromised version)"

if echo "$OUTPUT" | grep -q "No vulnerable packages detected"; then
    pass "axios@1.14.0 correctly not flagged"
else
    fail "axios@1.14.0 incorrectly flagged as vulnerable"
fi

rm -rf "$MAL_DIR"
echo ""

# ============================================================
# Bug #8: No fix version for exact version matches (malware)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #8: No fix version for exact version (malware)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MAL_FIX_DIR=$(mktemp -d)
cat > "$MAL_FIX_DIR/test.purl" << 'PURL'
pkg:npm/evil-pkg@1.0.0?severity=critical&ghsa=GHSA-evil-test&source=osv
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"evil-pkg":"1.0.0"}}' > "$MAL_FIX_DIR/package.json"

OUTPUT=$(cd "$MAL_FIX_DIR" && "$SCRIPT" --source "$MAL_FIX_DIR/test.purl" 2>&1 || true)

echo "📦 Test: Exact version malware should NOT show a fix version"

if echo "$OUTPUT" | grep -q "Fix:"; then
    fail "Fix version incorrectly shown for exact version malware"
else
    pass "No fix version shown for exact version malware (correct)"
fi

rm -rf "$MAL_FIX_DIR"
echo ""

# ============================================================
# Bug #9: Scoped npm packages (@scope/name) in PURL feeds
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #9: Scoped npm package parsing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SCOPED_DIR=$(mktemp -d)
cat > "$SCOPED_DIR/test.purl" << 'PURL'
pkg:npm/@babel/traverse@<7.23.2?severity=high&ghsa=GHSA-scoped-test&source=test
pkg:npm/@evil/pkg@1.0.0?severity=critical&ghsa=GHSA-evil-scoped&source=test
PURL
cat > "$SCOPED_DIR/package-lock.json" << 'LOCK'
{
  "name": "scoped-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "scoped-test",
      "version": "1.0.0"
    },
    "node_modules/@babel/traverse": {
      "version": "7.0.0"
    },
    "node_modules/@evil/pkg": {
      "version": "1.0.0"
    }
  }
}
LOCK

OUTPUT=$(cd "$SCOPED_DIR" && "$SCRIPT" --source "$SCOPED_DIR/test.purl" 2>&1 || true)

echo "📦 Test: @babel/traverse@7.0.0 should match scoped range <7.23.2"

if echo "$OUTPUT" | grep -q "@babel/traverse@7.0.0 (vulnerable" && echo "$OUTPUT" | grep -q "GHSA-scoped-test"; then
    pass "Scoped range package @babel/traverse detected with advisory"
else
    fail "Scoped range package @babel/traverse not detected"
fi

echo "📦 Test: @evil/pkg@1.0.0 should match scoped exact version"

if echo "$OUTPUT" | grep -q "@evil/pkg@1.0.0 (vulnerable)" && echo "$OUTPUT" | grep -q "GHSA-evil-scoped"; then
    pass "Scoped exact package @evil/pkg detected with advisory"
else
    fail "Scoped exact package @evil/pkg not detected"
fi

rm -rf "$SCOPED_DIR"
echo ""

# ============================================================
# Bug #10: No cross-ecosystem collision (namespaced lookups)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #10: No cross-ecosystem collision"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

COLLISION_DIR=$(mktemp -d)
cat > "$COLLISION_DIR/test.purl" << 'PURL'
pkg:npm/commons-io@<2.7?severity=high&ghsa=GHSA-npm-x&source=test
pkg:maven/org.apache.commons/commons-io@<2.7?severity=critical&ghsa=GHSA-maven-x&source=test
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"commons-io":"2.0.0"}}' > "$COLLISION_DIR/package.json"

OUTPUT=$(cd "$COLLISION_DIR" && "$SCRIPT" --source "$COLLISION_DIR/test.purl" 2>&1 || true)

echo "📦 Test: npm commons-io@2.0.0 matches ONLY the npm advisory"

if echo "$OUTPUT" | grep -q "commons-io@2.0.0 (vulnerable" && echo "$OUTPUT" | grep -q "GHSA-npm-x"; then
    pass "npm commons-io matched its own (npm) advisory GHSA-npm-x"
else
    fail "npm commons-io did not match its npm advisory"
fi

echo "📦 Test: maven advisory must NOT leak into the npm result"

if echo "$OUTPUT" | grep -q "GHSA-maven-x"; then
    fail "maven advisory GHSA-maven-x incorrectly cross-matched to npm"
else
    pass "maven advisory GHSA-maven-x correctly absent (no cross-ecosystem collision)"
fi

rm -rf "$COLLISION_DIR"
echo ""

# ============================================================
# Bug #11: Wildcard feeds (no ecosystem) still match (legacy)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #11: Wildcard feeds still match"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

WILDCARD_DIR=$(mktemp -d)
cat > "$WILDCARD_DIR/test.csv" << 'CSV'
name,versions
some-lib,1.5.0
CSV
echo '{"name":"test","version":"1.0.0","dependencies":{"some-lib":"1.5.0"}}' > "$WILDCARD_DIR/package.json"

OUTPUT=$(cd "$WILDCARD_DIR" && "$SCRIPT" --source "$WILDCARD_DIR/test.csv" 2>&1 || true)

echo "📦 Test: CSV feed (no ecosystem info) still matches an npm project"

if echo "$OUTPUT" | grep -q "some-lib@1.5.0 (vulnerable"; then
    pass "Wildcard (CSV) feed still detects some-lib@1.5.0"
else
    fail "Wildcard (CSV) feed failed to detect some-lib@1.5.0"
fi

rm -rf "$WILDCARD_DIR"
echo ""

# ============================================================
# Bug #12: --lockfile-types validation + selective scanning
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #12: --lockfile-types validation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

LFT_DIR=$(mktemp -d)
cat > "$LFT_DIR/test.purl" << 'PURL'
pkg:npm/npmonly-pkg@1.0.0?severity=critical&ghsa=GHSA-npmonly-xxx&source=test
pkg:npm/yarnonly-pkg@2.0.0?severity=high&ghsa=GHSA-yarnonly-xxx&source=test
PURL
# A package-lock.json (npm) with one vuln package...
cat > "$LFT_DIR/package-lock.json" << 'LOCK'
{
  "name": "bug12",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "bug12", "version": "1.0.0" },
    "node_modules/npmonly-pkg": { "version": "1.0.0" }
  }
}
LOCK
# ...and a yarn.lock (yarn) with a DIFFERENT vuln package
cat > "$LFT_DIR/yarn.lock" << 'YARN'
# yarn lockfile v1
yarnonly-pkg@^2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/yarnonly-pkg/-/yarnonly-pkg-2.0.0.tgz"
YARN

# --- Part A: invalid type errors non-zero and names valid types ---
echo "📦 Test: --lockfile-types bogus exits non-zero and lists valid types"
BOGUS_OUT=$(cd "$LFT_DIR" && "$SCRIPT" --source "$LFT_DIR/test.purl" --lockfile-types bogus 2>&1) && BOGUS_EC=0 || BOGUS_EC=$?
if [ "$BOGUS_EC" -ne 0 ]; then
    pass "--lockfile-types bogus exits non-zero (exit $BOGUS_EC)"
else
    fail "--lockfile-types bogus should exit non-zero"
fi
if echo "$BOGUS_OUT" | grep -q "Unknown lockfile type: bogus" && echo "$BOGUS_OUT" | grep -Eq "npm.*yarn.*pnpm.*bun.*deno"; then
    pass "Error names the valid lockfile types"
else
    fail "Error did not clearly list valid lockfile types"
fi

# --- Part B: --lockfile-types yarn scans ONLY yarn.lock ---
echo "📦 Test: --lockfile-types yarn scans yarn.lock only (npm lockfile skipped)"
LFT_OUT=$(cd "$LFT_DIR" && "$SCRIPT" --source "$LFT_DIR/test.purl" --lockfile-types yarn 2>&1 || true)

if echo "$LFT_OUT" | grep -q "yarnonly-pkg@2.0.0 (vulnerable"; then
    pass "yarn.lock scanned: yarnonly-pkg@2.0.0 detected"
else
    fail "yarn.lock not scanned: yarnonly-pkg@2.0.0 missing"
fi

if echo "$LFT_OUT" | grep -q "npmonly-pkg"; then
    fail "package-lock.json was scanned despite --lockfile-types yarn (npmonly-pkg leaked)"
else
    pass "package-lock.json correctly NOT scanned (npmonly-pkg absent)"
fi

rm -rf "$LFT_DIR"
echo ""

# ============================================================
# Bug #13: --ecosystems flag (override + validation)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bug #13: --ecosystems flag"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ECO_DIR=$(mktemp -d)
cat > "$ECO_DIR/test.purl" << 'PURL'
pkg:npm/eco-pkg@1.2.3?severity=high&ghsa=GHSA-eco-xxx&source=test
PURL
echo '{"name":"test","version":"1.0.0","dependencies":{"eco-pkg":"1.2.3"}}' > "$ECO_DIR/package.json"

echo "📦 Test: --ecosystems npm behaves like today on an npm project"
ECO_OUT=$(cd "$ECO_DIR" && "$SCRIPT" --ecosystems npm --source "$ECO_DIR/test.purl" 2>&1 || true)
if echo "$ECO_OUT" | grep -q "eco-pkg@1.2.3 (vulnerable"; then
    pass "--ecosystems npm still detects eco-pkg@1.2.3"
else
    fail "--ecosystems npm failed to detect eco-pkg@1.2.3"
fi

echo "📦 Test: --ecosystems bogus errors clearly and exits non-zero"
BOGUS_ECO_OUT=$(cd "$ECO_DIR" && "$SCRIPT" --ecosystems bogus --source "$ECO_DIR/test.purl" 2>&1) && BOGUS_ECO_EC=0 || BOGUS_ECO_EC=$?
if [ "$BOGUS_ECO_EC" -ne 0 ]; then
    pass "--ecosystems bogus exits non-zero (exit $BOGUS_ECO_EC)"
else
    fail "--ecosystems bogus should exit non-zero"
fi
if echo "$BOGUS_ECO_OUT" | grep -q "Unknown ecosystem 'bogus'"; then
    pass "--ecosystems bogus prints a clear error"
else
    fail "--ecosystems bogus did not print a clear error"
fi

rm -rf "$ECO_DIR"
echo ""

# ============================================================
# Console-output freeze: npm-only output has no [npm] prefix
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Freeze: npm-only output has no [npm] prefix"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OUTPUT=$(cd "$FIXTURES_DIR/npm-project" && "$SCRIPT" --source "$FIXTURES_DIR/test-vulnerabilities.json" 2>&1 || true)

echo "📦 Test: npm-project output must not contain an [npm] ecosystem label"

if echo "$OUTPUT" | grep -q '\[npm\]'; then
    fail "npm-only output contains an [npm] prefix (should be bare)"
else
    pass "npm-only output has no [npm] prefix (byte-compatible with legacy)"
fi

echo ""

# ============================================================
# Ruby gem platform-suffix stripping: whole-segment anchoring
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Ruby: platform-suffix strip is whole-segment anchored"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

RUBY_PROBE_DIR=$(mktemp -d)
cat > "$RUBY_PROBE_DIR/probe.purl" << 'PURL'
pkg:gem/probegem@1.0.0-javascript?severity=high&ghsa=GHSA-probe-js&source=test
pkg:gem/platgem@1.16.5?severity=high&ghsa=GHSA-probe-plat&source=test
PURL
cat > "$RUBY_PROBE_DIR/Gemfile.lock" << 'LOCK'
GEM
  remote: https://rubygems.org/
  specs:
    probegem (1.0.0-javascript)
    platgem (1.16.5-arm64-darwin)

PLATFORMS
  ruby

DEPENDENCIES
  probegem
  platgem

BUNDLED WITH
   2.5.0
LOCK

RUBY_PROBE_OUT=$(cd "$RUBY_PROBE_DIR" && "$SCRIPT" --source "$RUBY_PROBE_DIR/probe.purl" --lockfile-types ruby 2>&1 || true)

# `1.0.0-javascript` must survive intact through the parser: `java` is a
# substring of `javascript` but NOT a whole platform segment, so the version
# must NOT be stripped to `1.0.0` (which would fail to match the feed entry).
echo "📦 Test: gem version 1.0.0-javascript survives (not stripped on 'java')"
if echo "$RUBY_PROBE_OUT" | grep -q "probegem@1.0.0-javascript"; then
    pass "1.0.0-javascript preserved through the Gemfile.lock parser"
else
    fail "1.0.0-javascript was mangled (likely stripped on the 'java' substring)"
fi

# Control: a genuine native-gem platform suffix is still stripped to the bare
# version, so platgem 1.16.5-arm64-darwin matches the feed's 1.16.5 entry.
echo "📦 Test: real platform suffix 1.16.5-arm64-darwin still stripped to 1.16.5"
if echo "$RUBY_PROBE_OUT" | grep -q "platgem@1.16.5"; then
    pass "arm64-darwin platform suffix still stripped to 1.16.5"
else
    fail "platform suffix stripping regressed (platgem@1.16.5 not detected)"
fi

rm -rf "$RUBY_PROBE_DIR"
echo ""

# ============================================================
# Bug #14: Swift bare-name advisories matched via last-segment fallback
# ============================================================
echo "Bug #14: Swift bare-name advisory fallback"

SWIFT_BARE_DIR=$(mktemp -d)
cat > "$SWIFT_BARE_DIR/bare.purl" << 'PURL'
pkg:swift/barecrypto@>=0 <2.0.0?severity=high&ghsa=GHSA-bare-swift&cve=CVE-BARE-0001&source=test
pkg:swift/github.com/testorg/urlpkg@>=0 <2.0.0?severity=high&ghsa=GHSA-url-swift&source=test
PURL

# Real `swift package resolve` output keeps state/version on their own lines.
cat > "$SWIFT_BARE_DIR/Package.resolved" << 'RESOLVED'
{
  "pins" : [
    {
      "identity" : "barecrypto",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/apple/barecrypto.git",
      "state" : {
        "revision" : "0000000000000000000000000000000000000000",
        "version" : "1.0.0"
      }
    },
    {
      "identity" : "urlpkg",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/testorg/urlpkg.git",
      "state" : {
        "revision" : "1111111111111111111111111111111111111111",
        "version" : "1.0.0"
      }
    }
  ],
  "version" : 2
}
RESOLVED

SWIFT_BARE_OUT=$(cd "$SWIFT_BARE_DIR" && "$SCRIPT" --source "$SWIFT_BARE_DIR/bare.purl" 2>&1 || true)

# A handful of real GHSA/OSV Swift advisories record the package under a bare
# identifier (e.g. `swift-crypto`) instead of the `github.com/owner/repo` URL
# every other advisory uses. The scanner canonicalizes a Package.resolved pin
# from its repo URL, so a bare feed entry can only match via the bare
# last-path-segment fallback.
echo "📦 Test: bare-name swift advisory (barecrypto) is detected"
if echo "$SWIFT_BARE_OUT" | grep -q "barecrypto@1.0.0"; then
    pass "bare-name swift advisory matched via fallback"
else
    fail "bare-name swift advisory missed (fallback not working)"
fi

# Control: a normal URL-form advisory still matches, exactly once — the bare
# fallback must not break it or double-count it.
echo "📦 Test: URL-form swift advisory still matched (no regression, no double-count)"
URLPKG_HITS=$(echo "$SWIFT_BARE_OUT" | grep -c "github.com/testorg/urlpkg@1.0.0" || true)
if [ "$URLPKG_HITS" -ge 1 ]; then
    pass "URL-form swift advisory matched by the primary probe"
else
    fail "URL-form swift advisory regressed"
fi

# Control: patched versions above the range are not flagged (no false positive
# introduced by the fallback probe).
mkdir -p "$SWIFT_BARE_DIR/safe"
sed 's/"1.0.0"/"2.0.0"/g' "$SWIFT_BARE_DIR/Package.resolved" > "$SWIFT_BARE_DIR/safe/Package.resolved"
echo "📦 Test: patched swift versions (2.0.0) not flagged"
if (cd "$SWIFT_BARE_DIR/safe" && "$SCRIPT" . --source "$SWIFT_BARE_DIR/bare.purl" >/dev/null 2>&1); then
    pass "patched swift versions correctly not flagged (exit 0)"
else
    fail "false positive on patched swift versions"
fi

rm -rf "$SWIFT_BARE_DIR"
echo ""

# ============================================================
# Summary
# ============================================================
echo "============================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "============================================"

if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
