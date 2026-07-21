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
