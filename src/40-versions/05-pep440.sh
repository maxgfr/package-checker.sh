# PEP 440 version comparator (Python / PyPI ordering).
#
# Routed to from compare_versions_eco when CHECK_ECO=pypi. A wrong ordering in a
# security tool silently produces false negatives, so this follows the reference
# `packaging` sort-key algorithm (epoch, release, pre, post, dev, local) exactly:
#
#   version := [N!]release[{a|b|rc}N][.postN][.devN][+local]
#
#   * epoch   (N!)     compares first, numerically (default 0).
#   * release (x.y.z)  numeric, dot-split, zero-padded (1.0 == 1.0.0,
#                      1.0.10 > 1.0.2).
#   * ordering within a release:
#         dev  <  pre(a<b<rc)  <  final  <  post
#     Precisely, mirroring packaging's _cmpkey:
#       - a version with ONLY a .devN (no pre, no post) ranks BELOW every
#         pre-release of that release   (1.0.dev1 < 1.0a1);
#       - a version with no pre-release ranks ABOVE all pre-releases
#         (1.0rc1 < 1.0), and a post-release ranks above the final
#         (1.0 < 1.0.post1);
#       - a trailing .devN drops a version just below its non-dev sibling
#         (1.0rc1.dev1 < 1.0rc1, 1.0.post1.dev1 < 1.0.post1);
#       - pre/post/dev NUMBERS compare numerically.
#   * local (+...) is IGNORED for ordering/range matching (1.0+local == 1.0).
#
# Normalization before comparing (case-insensitive):
#   alpha->a  beta->b  c|pre|preview->rc ; post|rev|r and a bare -N suffix
#   -> .postN ; optional . / - / _ separators between parts (1.0-a1 == 1.0a1) ;
#   a leading `v` is stripped (V1.0 == 1.0) ; implicit numbers default to 0
#   (1.0a == 1.0a0).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.

# Parse one normalized PEP 440 version into the _PEP_* globals:
#   _PEP_EPOCH                       epoch integer
#   _PEP_REL                         array of release segments (integers)
#   _PEP_PRERANK  _PEP_PRELET  _PEP_PRENUM
#         PRERANK: 0 = dev-only (below pre-releases), 1 = has pre-release,
#                  2 = no pre-release (final/post). PRELET: a=0 b=1 rc=2.
#   _PEP_POSTRANK _PEP_POSTNUM       POSTRANK 0 = no post, 1 = has post.
#   _PEP_DEVRANK  _PEP_DEVNUM        DEVRANK  0 = has dev,  1 = no dev.
_pep440_parse() {
    local v="$1"

    # Trim surrounding whitespace, lowercase, strip a leading `v`, drop local.
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v,,}"
    v="${v#v}"
    v="${v%%+*}"

    # Epoch: leading "N!".
    local epoch=0
    case "$v" in
        *'!'*) epoch="${v%%!*}"; v="${v#*!}" ;;
    esac
    _PEP_EPOCH="$epoch"

    # One regex splits release / pre / post / dev. Group map:
    #   1 release   4 pre-letter   5 pre-num
    #   6 post-any  7 implicit -N post   10 explicit post-num
    #   11 dev-any  13 dev-num
    local re='^([0-9]+(\.[0-9]+)*)([-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?((-[0-9]+)|([-_.]?(post|rev|r)[-_.]?([0-9]+)?))?([-_.]?(dev)[-_.]?([0-9]+)?)?$'

    if [[ "$v" =~ $re ]]; then
        # Release segments.
        local rel="${BASH_REMATCH[1]}"
        local IFS='.'
        _PEP_REL=($rel)
        unset IFS

        # Pre-release.
        local prelet="${BASH_REMATCH[4]}"
        if [ -n "$prelet" ]; then
            _PEP_PRENUM="${BASH_REMATCH[5]:-0}"
            case "$prelet" in
                a|alpha)          _PEP_PRELET=0 ;;
                b|beta)           _PEP_PRELET=1 ;;
                c|rc|pre|preview) _PEP_PRELET=2 ;;
                *)                _PEP_PRELET=0 ;;
            esac
        else
            _PEP_PRENUM=0
            _PEP_PRELET=0
        fi

        # Post-release (implicit "-N" or explicit post/rev/r[N]).
        local has_post=0 postnum=0
        if [ -n "${BASH_REMATCH[6]}" ]; then
            has_post=1
            if [ -n "${BASH_REMATCH[7]}" ]; then
                postnum="${BASH_REMATCH[7]#-}"
            else
                postnum="${BASH_REMATCH[10]:-0}"
            fi
        fi
        _PEP_POSTRANK="$has_post"
        _PEP_POSTNUM="$postnum"

        # Dev-release.
        local has_dev=0 devnum=0
        if [ -n "${BASH_REMATCH[11]}" ]; then
            has_dev=1
            devnum="${BASH_REMATCH[13]:-0}"
        fi
        _PEP_DEVNUM="$devnum"
        # DEVRANK: present sorts first (0), absent sorts last (1 == +inf).
        if [ "$has_dev" = 1 ]; then _PEP_DEVRANK=0; else _PEP_DEVRANK=1; fi

        # PRERANK: dev-only (no pre, no post, has dev) sinks below pre-releases.
        if [ -n "$prelet" ]; then
            _PEP_PRERANK=1
        elif [ "$has_post" = 0 ] && [ "$has_dev" = 1 ]; then
            _PEP_PRERANK=0
        else
            _PEP_PRERANK=2
        fi
    else
        # Unparseable tail: treat the whole thing as a bare release so ordering
        # stays deterministic rather than crashing the scan.
        local IFS='.'
        _PEP_REL=(${v%%[!0-9.]*})
        unset IFS
        [ "${#_PEP_REL[@]}" -eq 0 ] && _PEP_REL=(0)
        _PEP_PRERANK=2; _PEP_PRELET=0; _PEP_PRENUM=0
        _PEP_POSTRANK=0; _PEP_POSTNUM=0
        _PEP_DEVRANK=1;  _PEP_DEVNUM=0
    fi
}

compare_versions_pep440() {
    _pep440_parse "$1"
    local e1="$_PEP_EPOCH"
    local rel1=("${_PEP_REL[@]}")
    local prerank1="$_PEP_PRERANK" prelet1="$_PEP_PRELET" prenum1="$_PEP_PRENUM"
    local postrank1="$_PEP_POSTRANK" postnum1="$_PEP_POSTNUM"
    local devrank1="$_PEP_DEVRANK" devnum1="$_PEP_DEVNUM"

    _pep440_parse "$2"
    local e2="$_PEP_EPOCH"
    local rel2=("${_PEP_REL[@]}")
    local prerank2="$_PEP_PRERANK" prelet2="$_PEP_PRELET" prenum2="$_PEP_PRENUM"
    local postrank2="$_PEP_POSTRANK" postnum2="$_PEP_POSTNUM"
    local devrank2="$_PEP_DEVRANK" devnum2="$_PEP_DEVNUM"

    # 1. Epoch (numeric; 10# guards any leading zeros).
    if (( 10#$e1 < 10#$e2 )); then COMPARE_RESULT="-1"; return; fi
    if (( 10#$e1 > 10#$e2 )); then COMPARE_RESULT="1";  return; fi

    # 2. Release, segment by segment, zero-padded (missing segment == 0).
    local len1=${#rel1[@]} len2=${#rel2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2
    local i s1 s2
    for (( i = 0; i < maxlen; i++ )); do
        s1="${rel1[$i]:-0}"; s2="${rel2[$i]:-0}"
        if (( 10#$s1 < 10#$s2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$s1 > 10#$s2 )); then COMPARE_RESULT="1";  return; fi
    done

    # 3. Pre-release group (dev-only < pre < final/post).
    if [ "$prerank1" -lt "$prerank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$prerank1" -gt "$prerank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$prerank1" = 1 ]; then
        if [ "$prelet1" -lt "$prelet2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$prelet1" -gt "$prelet2" ]; then COMPARE_RESULT="1";  return; fi
        if (( 10#$prenum1 < 10#$prenum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$prenum1 > 10#$prenum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    # 4. Post-release (no post < post; then post number).
    if [ "$postrank1" -lt "$postrank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$postrank1" -gt "$postrank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$postrank1" = 1 ]; then
        if (( 10#$postnum1 < 10#$postnum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$postnum1 > 10#$postnum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    # 5. Dev-release (has dev < no dev; then dev number).
    if [ "$devrank1" -lt "$devrank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$devrank1" -gt "$devrank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$devrank1" = 0 ]; then
        if (( 10#$devnum1 < 10#$devnum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$devnum1 > 10#$devnum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    COMPARE_RESULT="0"
}
