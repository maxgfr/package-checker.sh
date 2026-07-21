#!/usr/bin/env bash
# Table-driven test harness for the ecosystem version comparators.
#
# Sources the built script.sh (the entrypoint guard in src/99-run.sh makes
# `source` safe — main() only runs when executed directly) and drives rows of
#   eco|v1|v2|expected(-1/0/1)
# through compare_versions_eco, asserting the resulting COMPARE_RESULT.
#
# Exercises the golang comparator (semver-2 prerelease + Go pseudo-versions)
# and proves the dispatch falls back to the frozen npm compare_versions.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/script.sh"

PASS=0
FAIL=0

check() {
    local eco="$1" v1="$2" v2="$3" expected="$4"
    COMPARE_RESULT=""
    compare_versions_eco "$eco" "$v1" "$v2"
    if [ "$COMPARE_RESULT" = "$expected" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: compare_versions_eco $eco '$v1' '$v2' => '$COMPARE_RESULT' (expected '$expected')"
    fi
}

# Rows: eco|v1|v2|expected. Symmetric expectations are added automatically for
# ordered pairs so both directions of the comparator are exercised.
ROWS=(
    # --- Go: leading v / build metadata normalization ---
    "golang|v1.0.0|1.0.0|0"
    "golang|2.0.0+incompatible|2.0.0|0"
    "golang|1.0.0+meta1|1.0.0+meta2|0"
    # --- Go: numeric base comparison (string compare would get 9 vs 11 wrong) ---
    "golang|1.9.0|1.11.0|-1"
    # --- Go: pseudo-versions ---
    "golang|v0.0.0-20191109021931-daa7c04131f5|v1.0.0|-1"
    "golang|v0.0.0-20191109021931-daa7c04131f5|v0.0.0-20201230120000-abcdef123456|-1"
    # --- Go: semver-2 prerelease precedence ---
    "golang|1.0.0-alpha|1.0.0|-1"
    "golang|1.0.0-alpha|1.0.0-beta|-1"
    "golang|1.0.0-alpha.1|1.0.0-alpha.2|-1"
    "golang|1.0.0-1|1.0.0-alpha|-1"
    "golang|1.0.0-rc.1|1.0.0|-1"
    "golang|1.0.0-alpha|1.0.0-alpha.1|-1"
    # --- Go: extra coverage ---
    "golang|1.0.0-alpha.beta|1.0.0-beta|-1"
    "golang|1.2.3|1.2.3|0"
    # --- npm dispatch fallback (proves compare_versions_eco routes to the
    #     frozen npm comparator for non-golang ecosystems) ---
    "npm|1.2.3|1.10.0|-1"
    "npm|1.2.3|1.2.3|0"
    "cargo|0.1.45|0.2.0|-1"
)

for row in "${ROWS[@]}"; do
    IFS='|' read -r eco v1 v2 expected <<< "$row"
    check "$eco" "$v1" "$v2" "$expected"
    # Also assert the mirror comparison for ordered pairs.
    if [ "$expected" = "-1" ]; then
        check "$eco" "$v2" "$v1" "1"
    elif [ "$expected" = "1" ]; then
        check "$eco" "$v2" "$v1" "-1"
    else
        check "$eco" "$v2" "$v1" "0"
    fi
done

echo ""
echo "=========================================="
echo "Version-compare harness: $PASS passed, $FAIL failed"
echo "=========================================="

[ "$FAIL" -eq 0 ]
