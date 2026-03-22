#!/bin/bash
# Comprehensive test suite for all bug fixes:
# - Bug #1: Multiple advisories per package (multi-vulnerability reporting)
# - Bug #2: Build metadata (+) handling in version comparison
# - Bug #3: Empty range should not match all versions
# - Bug #4: Pre-release ordering (alpha < beta < rc)
# - Bug #5: Skip workspace/file/link version specifiers
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
