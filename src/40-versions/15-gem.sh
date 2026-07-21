# RubyGems version comparator (Gem::Version ordering). Routed to from
# compare_versions_eco when CHECK_ECO=gem.
#
# RubyGems ordering, verified segment-by-segment against real `Gem::Version`
# (ruby -rrubygems):
#   * a literal `-` is canonicalized to `.pre.` BEFORE splitting, so
#     `1.0-1` and `1.0.pre.1` parse to identical segments (and compare equal);
#   * the (dash-canonicalized) string is tokenized into segments by BOTH the
#     literal dots AND every digit/letter boundary — `2a1` -> `2`, `a`, `1`
#     (same as the explicit `2.a.1`), `1.0.b1` -> `1`, `0`, `b`, `1`;
#   * segments are compared left to right; a missing trailing segment on the
#     shorter side defaults to `0` (`1.0 == 1.0.0`);
#   * two numeric segments compare numerically (`1.0.10 > 1.0.2`);
#   * two string segments compare lexically (ASCII, `1.0.a < 1.0.b`);
#   * a string segment ALWAYS ranks below a numeric segment at the same
#     position — including a numeric segment that only exists because the
#     other side ran out (padded to `0`) — which is exactly what makes any
#     version with a trailing string segment a prerelease of its release
#     (`1.0.0.pre.1 < 1.0.0`, `3.0.0.beta1 < 3.0.0`).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path (tokenizing is a pure bash regex/slice loop,
# same style as the go/pep440 comparators' identifier loops).

# Tokenize a (dash-canonicalized) version string into the global array
# _GEM_SEGS: every maximal digit-run or letter-run becomes one segment; dots
# and any other stray character are pure separators and are dropped.
_gem_tokenize() {
    local s="$1"
    _GEM_SEGS=()
    local tok
    while [ -n "$s" ]; do
        if [[ "$s" =~ ^[0-9]+ ]]; then
            tok="${BASH_REMATCH[0]}"
            _GEM_SEGS+=("$tok")
            s="${s:${#tok}}"
        elif [[ "$s" =~ ^[A-Za-z]+ ]]; then
            tok="${BASH_REMATCH[0]}"
            _GEM_SEGS+=("$tok")
            s="${s:${#tok}}"
        else
            # '.' separator (or any other stray char, e.g. a leftover '+'):
            # skip exactly one character and keep scanning.
            s="${s:1}"
        fi
    done
}

compare_versions_gem() {
    # Canonicalize: '-' introduces a prerelease, identically to '.pre.'.
    local v1="${1//-/.pre.}"
    local v2="${2//-/.pre.}"

    _gem_tokenize "$v1"
    local -a segs1=("${_GEM_SEGS[@]}")
    _gem_tokenize "$v2"
    local -a segs2=("${_GEM_SEGS[@]}")

    local len1=${#segs1[@]} len2=${#segs2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2

    local i s1 s2 isnum1 isnum2
    for (( i = 0; i < maxlen; i++ )); do
        s1="${segs1[$i]:-0}"
        s2="${segs2[$i]:-0}"
        [ "$s1" = "$s2" ] && continue

        case "$s1" in ''|*[!0-9]*) isnum1=0 ;; *) isnum1=1 ;; esac
        case "$s2" in ''|*[!0-9]*) isnum2=0 ;; *) isnum2=1 ;; esac

        if [ "$isnum1" = 1 ] && [ "$isnum2" = 1 ]; then
            # 10# guards against octal misinterpretation of leading zeros.
            if [ "$((10#$s1))" -lt "$((10#$s2))" ]; then COMPARE_RESULT="-1"; return; fi
            if [ "$((10#$s1))" -gt "$((10#$s2))" ]; then COMPARE_RESULT="1"; return; fi
        elif [ "$isnum1" = 0 ] && [ "$isnum2" = 1 ]; then
            COMPARE_RESULT="-1"; return   # string segment < numeric segment
        elif [ "$isnum1" = 1 ] && [ "$isnum2" = 0 ]; then
            COMPARE_RESULT="1"; return    # numeric segment > string segment
        else
            if [[ "$s1" < "$s2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$s1" > "$s2" ]]; then COMPARE_RESULT="1"; return; fi
        fi
    done

    COMPARE_RESULT="0"
}
