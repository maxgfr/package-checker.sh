# NuGet version comparator (NuGet.Versioning ordering). Routed to from
# compare_versions_eco when CHECK_ECO=nuget.
#
# NuGet versions are SemVer 2.0.0 PLUS an optional 4th numeric Revision
# component: Major.Minor.Patch[.Revision][-prerelease][+metadata]. This is a
# WRAPPER around the frozen 3-part npm compare_versions (never modified, per
# the golang/pep440/gem/maven comparators' pattern) rather than a call into
# it, because compare_versions only knows Major.Minor.Patch — it has no
# concept of a 4th part, so it cannot be reused as-is:
#   - build metadata (+meta) is stripped before comparison (SemVer 2.0.0:
#     MUST be ignored for precedence), same as the go comparator strips
#     +incompatible/+meta;
#   - the Major.Minor.Patch.Revision QUAD is compared here directly, numeric
#     part by numeric part; a missing Revision defaults to 0 (1.0.0 ==
#     1.0.0.0), same rule the base compare_versions applies to a missing
#     Patch;
#   - once the quad is equal, the pre-release tail is compared using full
#     SemVer-2 rules: dot-split identifiers, numeric identifiers compare
#     numerically and rank below alphanumeric ones, and a longer identifier
#     list that is a prefix-superset of the shorter one wins — the exact same
#     dot-split loop as compare_versions_go's pre-release tail (reused here
#     verbatim, adapted to the case-insensitive rule below), NOT
#     compare_versions' whole-pre-release-string lexical compare (which would
#     mis-rank "beta.10" below "beta.9");
#   - NuGet pre-release labels are compared CASE-INSENSITIVELY (this is where
#     NuGet actually diverges from strict SemVer 2.0.0, which is
#     case-sensitive): "1.0.0-BETA" == "1.0.0-beta". Both pre-release tails
#     are lowercased before the dot-split comparison; the numeric quad itself
#     has no case to normalize.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.
compare_versions_nuget() {
    # Strip build metadata (+meta) — ignored for precedence per SemVer 2.0.0.
    local v1="${1%%+*}"
    local v2="${2%%+*}"

    # Split base (Major.Minor.Patch[.Revision]) from the pre-release tail.
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare the Major.Minor.Patch.Revision quad numerically ---
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)
    unset IFS
    local i n1 n2
    for i in 0 1 2 3; do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        if [ "$n1" -lt "$n2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$n1" -gt "$n2" ]; then COMPARE_RESULT="1"; return; fi
    done

    # --- Pre-release comparison (quads are equal) ---
    local pre1="" pre2=""
    [ "$v1" != "$base1" ] && pre1="${v1#*-}"
    [ "$v2" != "$base2" ] && pre2="${v2#*-}"

    # A version with a pre-release has LOWER precedence than one without.
    if [ -z "$pre1" ] && [ -z "$pre2" ]; then COMPARE_RESULT="0"; return; fi
    if [ -z "$pre1" ]; then COMPARE_RESULT="1"; return; fi
    if [ -z "$pre2" ]; then COMPARE_RESULT="-1"; return; fi

    # NuGet pre-release labels are case-insensitive: normalize before compare.
    pre1="${pre1,,}"
    pre2="${pre2,,}"

    # Both have a pre-release: compare dot-split identifiers left to right
    # (identical shape to compare_versions_go's pre-release loop).
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
