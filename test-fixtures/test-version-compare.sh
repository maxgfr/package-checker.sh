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
    "composer|7.4.0|7.4.3|-1"
    "composer|1.2.3|1.2.3|0"
    # --- PyPI (PEP 440) ---
    # epoch dominates everything
    "pypi|1!1.0|2.0|1"
    "pypi|2!1.0|1!2.0|1"
    # pre-release ranks below the final release
    "pypi|1.0a1|1.0|-1"
    # dev release ranks below pre-releases of the same release
    "pypi|1.0.dev1|1.0a1|-1"
    # pre-release ladder: a < b < rc < final
    "pypi|1.0a1|1.0b1|-1"
    "pypi|1.0b1|1.0rc1|-1"
    "pypi|1.0rc1|1.0|-1"
    # post release ranks above the final release
    "pypi|1.0.post1|1.0|1"
    # local version segment is ignored for ordering
    "pypi|1.0+local|1.0|0"
    # trailing-zero release equivalence and numeric (not lexical) segments
    "pypi|1.0|1.0.0|0"
    "pypi|1.0.10|1.0.2|1"
    # spelling aliases normalize to the canonical pre-release form
    "pypi|1.0c1|1.0rc1|0"
    "pypi|1.0-alpha1|1.0a1|0"
    # dev/post combinations
    "pypi|1.0.post1.dev1|1.0.post1|-1"
    "pypi|1.0rc1.dev1|1.0rc1|-1"
    # pre/post/dev numbers compare numerically
    "pypi|1.0.post2|1.0.post1|1"
    "pypi|1.0a2|1.0a1|1"
    "pypi|1.0.dev2|1.0.dev1|1"
    # plain release ordering + v-prefix strip
    "pypi|0.9|1.0|-1"
    "pypi|V1.0|1.0|0"
    # --- RubyGems (Gem::Version) ---
    # a trailing string segment is a prerelease of its release
    "gem|1.0.a|1.0|-1"
    "gem|1.0.0.pre.1|1.0.0|-1"
    # numeric segments compare numerically, not lexically
    "gem|1.0.10|1.0.2|1"
    # missing trailing segments default to 0
    "gem|1.0|1.0.0|0"
    # string segments compare lexically
    "gem|1.0.a|1.0.b|-1"
    # mixed digit/letter segment, numeric tail breaks the tie
    "gem|1.0.b1|1.0.b2|-1"
    # differing segment counts (4-segment RHS)
    "gem|2.2.3|2.2.6.4|-1"
    # an explicit extra numeric segment ranks ABOVE the shorter version
    "gem|1.0.0.1|1.0.0|1"
    "gem|3.0.0.beta1|3.0.0|-1"
    # '-' canonicalizes to '.pre.' before comparison
    "gem|1.0-1|1.0.pre.1|0"
    # mixed alphanumeric segment splits identically to the explicit dotted form
    "gem|2a1|2.a.1|0"
    "gem|1.2.3|1.2.3|0"
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
