# Maven version comparator (Apache Maven ComparableVersion ordering). Routed to
# from compare_versions_eco when CHECK_ECO=maven.
#
# This is a faithful port of org.apache.maven.artifact.versioning.ComparableVersion
# (verified against apache/maven maven-3.9.x). A wrong ordering in a security tool
# silently produces false negatives, so the algorithm is reproduced exactly rather
# than approximated:
#
# PARSING (parseVersion): the lowercased string is tokenized into a tree of Items
# (INT / STRING / nested LIST). Separators are '.' and '-', AND every digit<->letter
# transition also splits a token. A '-' (and each digit/letter transition) opens a
# new nested sub-list, so "1.0alpha1" and "1.0-alpha-1" parse to the identical tree
# [1, [alpha, [1]]]. An empty token at a separator inserts an integer 0.
#
# QUALIFIER RANKING (comparableQualifier): known qualifiers map to their index in
#   alpha(0) < beta(1) < milestone(2) < rc(3) < snapshot(4) < ""(5, release) < sp(6)
# and unknown qualifiers map to the string "7-<qualifier>". Qualifiers are compared
# as STRINGS (byte order), so an unknown qualifier ("7-xyz") sorts lexically AFTER
# sp and the release ("5"/"6") — e.g. 1.0-xyz > 1.0. Aliases (case-insensitive):
# ga/final/release -> "" ; cr -> rc ; and a single letter a/b/m -> alpha/beta/
# milestone but ONLY when immediately followed by a digit (a1 == alpha-1, while a
# trailing bare "a" stays the unknown qualifier "a").
#
# ITEM COMPARISON:
#   * INT vs INT      : numeric (arbitrary precision — length then byte compare).
#   * INT vs STRING   : INT wins (1.1 > 1-sp, so a numeric item outranks a qualifier).
#   * INT vs LIST     : INT wins.
#   * STRING vs STRING: comparableQualifier byte compare.
#   * STRING vs LIST  : STRING loses (-1).
#   * LIST vs LIST    : element-wise; a shorter list pads with a "null" item and the
#                       missing side's compare is inverted (x.compareTo(null)).
#   * X vs null       : INT 0 == null; STRING vs null == comparableQualifier vs "5"
#                       (release); LIST vs null == firstChild vs null (empty == null).
#
# NORMALIZATION trims trailing "null" items (integer 0, release/empty qualifier,
# empty list) from each list, so 1.0 == 1.0.0 == 1-0 == 1.0-0. This is why a
# trailing 0 (1.0) equals a missing segment (1) yet 2.0.1 > 2.0.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout, no
# subshell in the hot path (the tree is built in flat bash arrays and walked with
# plain recursion — no command substitution, no external processes).

# Allocate one tree node. $1=type (0=int,1=string,2=list) $2=value. The node id
# is returned in _MV_RET; per-comparison state lives in dynamically-scoped locals
# declared by compare_versions_maven (_MV_TYPE / _MV_VAL / _MV_KIDS / _MV_N).
_mv_new() {
    _MV_TYPE[$_MV_N]="$1"
    _MV_VAL[$_MV_N]="$2"
    _MV_KIDS[$_MV_N]=""
    _MV_RET=$_MV_N
    _MV_N=$((_MV_N + 1))
}

# Append child node $2 to list node $1.
_mv_addkid() {
    if [ -z "${_MV_KIDS[$1]}" ]; then
        _MV_KIDS[$1]="$2"
    else
        _MV_KIDS[$1]="${_MV_KIDS[$1]} $2"
    fi
}

# Build a StringItem node from a raw (already-lowercased) qualifier token.
# $2=followedByDigit (1/0) enables the single-letter a/b/m aliases; ga/final/
# release/cr aliases always apply. Result id in _MV_RET.
_mv_new_string() {
    local val="$1"
    if [ "$2" = 1 ] && [ "${#val}" -eq 1 ]; then
        case "$val" in
            a) val="alpha" ;;
            b) val="beta" ;;
            m) val="milestone" ;;
        esac
    fi
    case "$val" in
        ga|final|release) val="" ;;
        cr) val="rc" ;;
    esac
    _mv_new 1 "$val"
}

# parseItem: a digit token becomes an INT node (leading zeros stripped, but at
# least one digit kept); anything else becomes a StringItem (followedByDigit=0).
_mv_parseitem() {
    if [ "$1" = 1 ]; then
        local v="$2"
        while [ "${#v}" -gt 1 ] && [ "${v:0:1}" = "0" ]; do v="${v:1}"; done
        _mv_new 0 "$v"
    else
        _mv_new_string "$2" 0
    fi
}

# comparableQualifier -> _MV_CQ. Known qualifiers map to their single-digit index;
# unknown qualifiers map to "7-<qualifier>" (so they byte-sort above sp/release).
_mv_cq() {
    case "$1" in
        alpha)     _MV_CQ="0" ;;
        beta)      _MV_CQ="1" ;;
        milestone) _MV_CQ="2" ;;
        rc)        _MV_CQ="3" ;;
        snapshot)  _MV_CQ="4" ;;
        "")        _MV_CQ="5" ;;
        sp)        _MV_CQ="6" ;;
        *)         _MV_CQ="7-$1" ;;
    esac
}

# Byte-order string compare -> _MV_CMP (LC_ALL=C is set by the entrypoint so this
# is a true code-point comparison, matching Java String.compareTo for this charset).
_mv_strcmp() {
    if [[ "$1" < "$2" ]]; then _MV_CMP=-1
    elif [[ "$1" > "$2" ]]; then _MV_CMP=1
    else _MV_CMP=0
    fi
}

# Arbitrary-precision numeric compare of two leading-zero-stripped digit strings
# -> _MV_CMP (shorter string is the smaller number; equal length falls back to
# byte compare, which equals numeric order for equal-length digit strings).
_mv_numcmp() {
    if [ "${#1}" -lt "${#2}" ]; then _MV_CMP=-1; return; fi
    if [ "${#1}" -gt "${#2}" ]; then _MV_CMP=1; return; fi
    _mv_strcmp "$1" "$2"
}

# isNull: integer 0, release/empty qualifier, or empty list. Returns 0 (true) when
# the node contributes nothing (subject to trailing trimming in normalize).
_mv_isnull() {
    case "${_MV_TYPE[$1]}" in
        0) [ "${_MV_VAL[$1]}" = "0" ] ;;
        1) [ -z "${_MV_VAL[$1]}" ] ;;
        2) [ -z "${_MV_KIDS[$1]}" ] ;;
    esac
}

# ListItem.normalize: drop trailing null items, continuing past non-null nested
# lists (matching Maven's `else if (!(lastItem instanceof ListItem)) break`).
_mv_normalize() {
    local -a kids=(${_MV_KIDS[$1]})
    local i cid
    for (( i = ${#kids[@]} - 1; i >= 0; i-- )); do
        cid="${kids[$i]}"
        if _mv_isnull "$cid"; then
            unset 'kids[$i]'
        elif [ "${_MV_TYPE[$cid]}" != 2 ]; then
            break
        fi
    done
    _MV_KIDS[$1]="${kids[*]}"
}

# parseVersion: tokenize $1 into a normalized Item tree; root list id -> _MV_RET.
_mv_parse() {
    local version="${1,,}"
    _mv_new 2 ""
    local root=$_MV_RET
    local -a stack=("$root")
    local list=$root
    local isDigit=0 startIndex=0
    local n=${#version} i c
    for (( i = 0; i < n; i++ )); do
        c="${version:i:1}"
        if [ "$c" = "." ]; then
            if [ "$i" -eq "$startIndex" ]; then
                _mv_new 0 "0"; _mv_addkid "$list" "$_MV_RET"
            else
                _mv_parseitem "$isDigit" "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
            fi
            startIndex=$((i + 1))
        elif [ "$c" = "-" ]; then
            if [ "$i" -eq "$startIndex" ]; then
                _mv_new 0 "0"; _mv_addkid "$list" "$_MV_RET"
            else
                _mv_parseitem "$isDigit" "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
            fi
            startIndex=$((i + 1))
            _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
        elif [[ "$c" == [0-9] ]]; then
            if [ "$isDigit" = 0 ] && [ "$i" -gt "$startIndex" ]; then
                if [ -n "${_MV_KIDS[$list]}" ]; then
                    _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
                fi
                _mv_new_string "${version:startIndex:i-startIndex}" 1; _mv_addkid "$list" "$_MV_RET"
                startIndex=$i
                _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
            fi
            isDigit=1
        else
            if [ "$isDigit" = 1 ] && [ "$i" -gt "$startIndex" ]; then
                _mv_parseitem 1 "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
                startIndex=$i
                _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
            fi
            isDigit=0
        fi
    done
    if [ "$n" -gt "$startIndex" ]; then
        if [ "$isDigit" = 0 ] && [ -n "${_MV_KIDS[$list]}" ]; then
            _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
        fi
        _mv_parseitem "$isDigit" "${version:startIndex}"; _mv_addkid "$list" "$_MV_RET"
    fi
    # Normalize deepest-first (Maven pops the creation stack LIFO).
    for (( i = ${#stack[@]} - 1; i >= 0; i-- )); do
        _mv_normalize "${stack[$i]}"
    done
    _MV_RET=$root
}

# Compare item $1 (always concrete) against item $2 (a node id, or "" for null).
# Result -> _MV_CMP (-1/0/1). Recurses for nested lists.
_mv_compare() {
    local l="$1" r="$2"
    local lt="${_MV_TYPE[$l]}"
    if [ -z "$r" ]; then
        case "$lt" in
            0) if [ "${_MV_VAL[$l]}" = "0" ]; then _MV_CMP=0; else _MV_CMP=1; fi ;;
            1) _mv_cq "${_MV_VAL[$l]}"; _mv_strcmp "$_MV_CQ" "5" ;;
            2) if [ -z "${_MV_KIDS[$l]}" ]; then
                   _MV_CMP=0
               else
                   local -a lk=(${_MV_KIDS[$l]}); _mv_compare "${lk[0]}" ""
               fi ;;
        esac
        return
    fi
    local rt="${_MV_TYPE[$r]}"
    case "$lt" in
        0) case "$rt" in
               0) _mv_numcmp "${_MV_VAL[$l]}" "${_MV_VAL[$r]}" ;;
               *) _MV_CMP=1 ;;
           esac ;;
        1) case "$rt" in
               0) _MV_CMP=-1 ;;
               1) _mv_cq "${_MV_VAL[$l]}"; local cl="$_MV_CQ"; _mv_cq "${_MV_VAL[$r]}"; _mv_strcmp "$cl" "$_MV_CQ" ;;
               2) _MV_CMP=-1 ;;
           esac ;;
        2) case "$rt" in
               0) _MV_CMP=-1 ;;
               1) _MV_CMP=1 ;;
               2) _mv_listcmp "$l" "$r" ;;
           esac ;;
    esac
}

# ListItem vs ListItem: walk children in lock-step, padding the shorter side with
# a null item and inverting that side's comparison (Maven's -1 * r.compareTo(l)).
_mv_listcmp() {
    local -a lk=(${_MV_KIDS[$1]}) rk=(${_MV_KIDS[$2]})
    local nl=${#lk[@]} nr=${#rk[@]}
    local max=$nl
    [ "$nr" -gt "$max" ] && max=$nr
    local i lc rc
    for (( i = 0; i < max; i++ )); do
        if [ "$i" -lt "$nl" ]; then lc="${lk[$i]}"; else lc=""; fi
        if [ "$i" -lt "$nr" ]; then rc="${rk[$i]}"; else rc=""; fi
        if [ -z "$lc" ]; then
            _mv_compare "$rc" ""
            _MV_CMP=$(( -1 * _MV_CMP ))
        else
            _mv_compare "$lc" "$rc"
        fi
        [ "$_MV_CMP" -ne 0 ] && return
    done
    _MV_CMP=0
}

compare_versions_maven() {
    # Byte-order collation for all qualifier/string compares (C locale == Java's
    # code-point order for the ASCII charset Maven versions use); standard IFS for
    # the array split/join the tree walk relies on. Both are function-local.
    local LC_ALL=C IFS=$' \t\n'
    local -a _MV_TYPE=() _MV_VAL=() _MV_KIDS=()
    local _MV_N=0 _MV_RET="" _MV_CMP=0 _MV_CQ=""

    _mv_parse "$1"; local r1=$_MV_RET
    _mv_parse "$2"; local r2=$_MV_RET
    _mv_compare "$r1" "$r2"
    COMPARE_RESULT="$_MV_CMP"
}
