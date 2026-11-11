# Composer (Packagist) version comparator. Routed to from compare_versions_eco
# when CHECK_ECO=composer.
#
# Composer's VersionParser normalizes before comparing, and its ordering is not
# semver's:
#   * a leading "v" is cosmetic (v2.4.0 == 2.4.0);
#   * the numeric part has any number of components (1.2.3.4), missing ones
#     count as 0;
#   * the stability suffix may be glued to the number (9.4.0RC1 == 9.4.0-RC1)
#     and orders dev < alpha (a) < beta (b) < RC < stable < patch (pl, p);
#   * "-pN" is a post-release patch (Magento 2.4.7-p4 > 2.4.7), not a
#     pre-release;
#   * the stability number compares numerically (beta10 > beta9).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell.

# Split a composer version into the globals _CV_NUMS (array of numeric parts),
# _CV_RANK (stability rank), _CV_NUM (stability number) and _CV_TAIL (anything
# left, compared lexically).
_composer_parse() {
    local v="${1,,}"
    v="${v%%+*}"
    [[ "$v" == v[0-9]* ]] && v="${v:1}"
    local nums="" rest=""
    if [[ "$v" =~ ^([0-9]+(\.[0-9]+)*)(.*)$ ]]; then
        nums="${BASH_REMATCH[1]}"
        rest="${BASH_REMATCH[3]}"
    else
        rest="$v"
    fi
    IFS='.' read -ra _CV_NUMS <<< "$nums"
    _CV_RANK=4 _CV_NUM=0 _CV_TAIL=""
    rest="${rest#[-._]}"
    [ -z "$rest" ] && return
    # The stability word must end the suffix or be followed by a separator:
    # "preview" is not "p" (patch) followed by "review".
    if [[ "$rest" =~ ^(dev|alpha|beta|rc|patch|pl|stable|a|b|c|p)[-._]?([0-9]*)([-._].*)?$ ]]; then
        case "${BASH_REMATCH[1]}" in
            dev) _CV_RANK=0 ;;
            alpha|a) _CV_RANK=1 ;;
            beta|b) _CV_RANK=2 ;;
            rc|c) _CV_RANK=3 ;;
            stable) _CV_RANK=4 ;;
            patch|pl|p) _CV_RANK=5 ;;
        esac
        _CV_NUM="${BASH_REMATCH[2]:-0}"
        _CV_TAIL="${BASH_REMATCH[3]}"
    else
        # Unknown suffix: rank it like a pre-release so it stays inside "<x.y.z".
        _CV_RANK=0
        _CV_TAIL="$rest"
    fi
}

compare_versions_composer() {
    _composer_parse "$1"
    local -a nums1=("${_CV_NUMS[@]}")
    local rank1=$_CV_RANK num1=$_CV_NUM tail1=$_CV_TAIL
    _composer_parse "$2"
    local -a nums2=("${_CV_NUMS[@]}")
    local rank2=$_CV_RANK num2=$_CV_NUM tail2=$_CV_TAIL

    local i n1 n2 len=${#nums1[@]}
    [ "${#nums2[@]}" -gt "$len" ] && len=${#nums2[@]}
    for (( i = 0; i < len; i++ )); do
        n1="${nums1[$i]:-0}" n2="${nums2[$i]:-0}"
        while [[ "$n1" == 0* && ${#n1} -gt 1 ]]; do n1="${n1#0}"; done
        while [[ "$n2" == 0* && ${#n2} -gt 1 ]]; do n2="${n2#0}"; done
        if (( ${#n1} != ${#n2} )); then
            (( ${#n1} < ${#n2} )) && COMPARE_RESULT=-1 || COMPARE_RESULT=1
            return
        fi
        if [[ "$n1" < "$n2" ]]; then COMPARE_RESULT=-1; return; fi
        if [[ "$n1" > "$n2" ]]; then COMPARE_RESULT=1; return; fi
    done

    if (( rank1 != rank2 )); then
        (( rank1 < rank2 )) && COMPARE_RESULT=-1 || COMPARE_RESULT=1
        return
    fi
    compare_digits "$num1" "$num2"
    [ "$DIGITS_CMP" = 0 ] || { COMPARE_RESULT="$DIGITS_CMP"; return; }
    _composer_tail_cmp "$tail1" "$tail2"
    COMPARE_RESULT="$DIGITS_CMP"
}

# Order the remainders after the stability number: a "-dev" tail precedes
# the bare release (1.0.0-RC1-dev < 1.0.0-RC1), which precedes any other
# tail; other tails compare part by part, numbers numerically
# (beta.1.2 < beta.1.10). Sets DIGITS_CMP.
_composer_tail_cmp() {
    local t1="${1#[-._]}" t2="${2#[-._]}" k1=1 k2=1
    [ -z "$t1" ] || k1=2
    [ -z "$t2" ] || k2=2
    [[ "$t1" != dev* ]] || k1=0
    [[ "$t2" != dev* ]] || k2=0
    if [ "$k1" != "$k2" ]; then
        [ "$k1" -lt "$k2" ] && DIGITS_CMP=-1 || DIGITS_CMP=1
        return
    fi
    DIGITS_CMP=0
    [ "$k1" = 2 ] || return 0
    local -a p1 p2
    IFS='-._' read -ra p1 <<< "$t1"
    IFS='-._' read -ra p2 <<< "$t2"
    local i n=${#p1[@]}
    [ "${#p2[@]}" -le "$n" ] || n=${#p2[@]}
    for (( i = 0; i < n; i++ )); do
        compare_digits "${p1[$i]:-0}" "${p2[$i]:-0}"
        [ "$DIGITS_CMP" = 0 ] || return 0
    done
}
