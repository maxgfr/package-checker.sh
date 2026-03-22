#!/bin/bash
# Test: Metadata collision bug
# When multiple advisories affect the same package with different ranges,
# the correct advisory metadata (GHSA, CVE, severity, source) must be
# displayed for the range that actually matches the installed version.
#
# Bug scenario (before fix):
#   - next has 3 advisories: >=9.5.5 <14.2.15, >=15.0.0 <15.0.6, >=16.0.0 <16.0.7
#   - next@16.0.3 should match >=16.0.0 <16.0.7 (GHSA-new-advisory-ccc / CVE-2025-33333)
#   - Before fix: metadata from the last-loaded advisory was shown instead

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$SCRIPT_DIR/script.sh"
FIXTURES_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"

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

echo "========================================"
echo "Test: Metadata collision with multiple"
echo "      advisories for the same package"
echo "========================================"
echo ""

# Run the script and capture output
cd "$TEST_DIR"
OUTPUT=$("$SCRIPT" --source "$FIXTURES_DIR/test-metadata-collision.purl" 2>&1 || true)

# ----------------------------------------------------------
# Test 1: next@16.0.3 should match >=16.0.0 <16.0.7 range
# ----------------------------------------------------------
echo "📦 Test 1: next@16.0.3 matches correct range"

if echo "$OUTPUT" | grep -q "next@16.0.3 (vulnerable - matches range: >=16.0.0 <16.0.7)"; then
    pass "next@16.0.3 matched range >=16.0.0 <16.0.7"
else
    fail "next@16.0.3 did not match expected range >=16.0.0 <16.0.7"
fi

# ----------------------------------------------------------
# Test 2: next@16.0.3 should show correct GHSA (not the old one)
# ----------------------------------------------------------
echo "📦 Test 2: next@16.0.3 displays correct advisory metadata"

if echo "$OUTPUT" | grep -q "GHSA-new-advisory-ccc"; then
    pass "Correct GHSA (GHSA-new-advisory-ccc) displayed for next@16.0.3"
else
    fail "Wrong or missing GHSA for next@16.0.3 (expected GHSA-new-advisory-ccc)"
fi

if echo "$OUTPUT" | grep -q "CVE-2025-33333"; then
    pass "Correct CVE (CVE-2025-33333) displayed for next@16.0.3"
else
    fail "Wrong or missing CVE for next@16.0.3 (expected CVE-2025-33333)"
fi

if echo "$OUTPUT" | grep -q "Severity: critical"; then
    pass "Correct severity (critical) displayed for next@16.0.3"
else
    fail "Wrong or missing severity for next@16.0.3 (expected critical)"
fi

# ----------------------------------------------------------
# Test 3: next@16.0.3 must NOT show metadata from other advisories
# ----------------------------------------------------------
echo "📦 Test 3: next@16.0.3 does NOT show wrong advisories"

if echo "$OUTPUT" | grep -q "GHSA-old-advisory-aaa"; then
    fail "GHSA-old-advisory-aaa (from >=9.5.5 <14.2.15) incorrectly shown"
else
    pass "GHSA-old-advisory-aaa correctly not shown for next@16.0.3"
fi

if echo "$OUTPUT" | grep -q "CVE-2024-11111"; then
    fail "CVE-2024-11111 (from >=9.5.5 <14.2.15) incorrectly shown"
else
    pass "CVE-2024-11111 correctly not shown for next@16.0.3"
fi

# ----------------------------------------------------------
# Test 4: express@4.18.0 should match >=4.17.0 <4.19.0 (not >=4.0.0 <4.17.0)
# ----------------------------------------------------------
echo "📦 Test 4: express@4.18.0 matches correct range and metadata"

if echo "$OUTPUT" | grep -q "express@4.18.0 (vulnerable - matches range: >=4.17.0 <4.19.0)"; then
    pass "express@4.18.0 matched range >=4.17.0 <4.19.0"
else
    fail "express@4.18.0 did not match expected range >=4.17.0 <4.19.0"
fi

if echo "$OUTPUT" | grep -q "GHSA-express-new-eee"; then
    pass "Correct GHSA (GHSA-express-new-eee) displayed for express@4.18.0"
else
    fail "Wrong or missing GHSA for express@4.18.0 (expected GHSA-express-new-eee)"
fi

if echo "$OUTPUT" | grep -q "CVE-2025-55555"; then
    pass "Correct CVE (CVE-2025-55555) displayed for express@4.18.0"
else
    fail "Wrong or missing CVE for express@4.18.0 (expected CVE-2025-55555)"
fi

if echo "$OUTPUT" | grep -q "Severity: low"; then
    pass "Correct severity (low) displayed for express@4.18.0"
else
    fail "Wrong or missing severity for express@4.18.0 (expected low)"
fi

if echo "$OUTPUT" | grep -q "GHSA-express-old-ddd"; then
    fail "GHSA-express-old-ddd (from >=4.0.0 <4.17.0) incorrectly shown"
else
    pass "GHSA-express-old-ddd correctly not shown for express@4.18.0"
fi

# ----------------------------------------------------------
# Summary
# ----------------------------------------------------------
echo ""
echo "========================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
