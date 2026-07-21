# Go module version comparator (semver-2 semantics, matching golang.org/x/mod
# semver ordering). Routed to from compare_versions_eco when CHECK_ECO=golang.
#
# Differences from the npm compare_versions this must NOT be folded into:
#   - a leading `v` is part of every Go module version and is stripped;
#   - `+incompatible` (and any `+build` metadata) is dropped, not treated as a
#     pre-release marker (npm's compare_versions would mis-rank 2.0.0+incompatible);
#   - pre-release identifiers follow the full semver-2 rules: dot-split, numeric
#     identifiers compare numerically and rank below alphanumeric ones, and a
#     longer identifier list wins when it is a prefix-superset of a shorter one.
# Go pseudo-versions (v0.0.0-20191109021931-daa7c04131f5) fall out of these
# rules for free: the timestamp+hash after the dash is a single alphanumeric
# pre-release identifier whose fixed-width timestamp prefix sorts chronologically
# under a plain lexical comparison.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.
compare_versions_go() {
    # Strip the leading module `v` and any build metadata (+incompatible/+meta).
    local v1="${1#v}"
    local v2="${2#v}"
    v1="${v1%%+*}"
    v2="${v2%%+*}"

    # Split base (x.y.z) from the pre-release tail (first '-' onward).
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare base x.y.z numerically ---
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)
    unset IFS
    local i n1 n2
    for i in 0 1 2; do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        if [ "$n1" -lt "$n2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$n1" -gt "$n2" ]; then COMPARE_RESULT="1"; return; fi
    done

    # --- Pre-release comparison (base versions are equal) ---
    local pre1="" pre2=""
    [ "$v1" != "$base1" ] && pre1="${v1#*-}"
    [ "$v2" != "$base2" ] && pre2="${v2#*-}"

    # A version with a pre-release has LOWER precedence than one without.
    if [ -z "$pre1" ] && [ -z "$pre2" ]; then COMPARE_RESULT="0"; return; fi
    if [ -z "$pre1" ]; then COMPARE_RESULT="1"; return; fi
    if [ -z "$pre2" ]; then COMPARE_RESULT="-1"; return; fi

    # Both have pre-release: compare dot-split identifiers left to right.
    local ids1 ids2
    IFS='.' read -ra ids1 <<< "$pre1"
    IFS='.' read -ra ids2 <<< "$pre2"
    local len1=${#ids1[@]}
    local len2=${#ids2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2

    local j id1 id2 isnum1 isnum2
    for (( j = 0; j < maxlen; j++ )); do
        # A larger set of pre-release fields (prefix-superset) wins.
        if [ "$j" -ge "$len1" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$j" -ge "$len2" ]; then COMPARE_RESULT="1"; return; fi

        id1="${ids1[$j]}"
        id2="${ids2[$j]}"
        [ "$id1" = "$id2" ] && continue

        # Numeric identifiers rank below alphanumeric ones; two numerics
        # compare numerically; two alphanumerics compare lexically (ASCII).
        case "$id1" in ''|*[!0-9]*) isnum1=0 ;; *) isnum1=1 ;; esac
        case "$id2" in ''|*[!0-9]*) isnum2=0 ;; *) isnum2=1 ;; esac

        if [ "$isnum1" = 1 ] && [ "$isnum2" = 1 ]; then
            if [ "$id1" -lt "$id2" ]; then COMPARE_RESULT="-1"; return; fi
            if [ "$id1" -gt "$id2" ]; then COMPARE_RESULT="1"; return; fi
        elif [ "$isnum1" = 1 ]; then
            COMPARE_RESULT="-1"; return
        elif [ "$isnum2" = 1 ]; then
            COMPARE_RESULT="1"; return
        else
            if [[ "$id1" < "$id2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$id1" > "$id2" ]]; then COMPARE_RESULT="1"; return; fi
        fi
    done

    COMPARE_RESULT="0"
}
