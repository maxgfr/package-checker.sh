get_base_version() {
    local version="$1"
    # Extract major.minor.patch, removing any pre-release or build metadata
    # Use parameter expansion to avoid subshell (much faster)
    local base="${version%%-*}"  # Remove everything after first dash
    base="${base%%+*}"           # Also remove build metadata after +
    echo "$base"
}

# Compare two semver versions
# Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
# OPTIMIZED: Sets COMPARE_RESULT global instead of echo (avoids subshell when called)
compare_versions() {
    # Build metadata never changes version precedence.
    local v1="$1"
    local v2="$2"
    v1="${v1%%+*}"
    v2="${v2%%+*}"
    # Tags such as v1.2.3 (cargo git deps, actions, swift) carry a cosmetic 'v'.
    [[ "$v1" == [vV][0-9]* ]] && v1="${v1:1}"
    [[ "$v2" == [vV][0-9]* ]] && v2="${v2:1}"

    # Split base (x.y.z[.w...]) from the pre-release tail (first '-' onward).
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare every numeric base part (missing parts count as 0) ---
    local -a parts1 parts2
    IFS='.' read -ra parts1 <<< "$base1"
    IFS='.' read -ra parts2 <<< "$base2"
    local i n1 n2 nparts=${#parts1[@]}
    [ "${#parts2[@]}" -gt "$nparts" ] && nparts=${#parts2[@]}
    [ "$nparts" -lt 3 ] && nparts=3
    for (( i = 0; i < nparts; i++ )); do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        # Decimal identifiers have no size limit in SemVer. Comparing lengths
        # then ASCII digits avoids shell integer overflow.
        while [[ "$n1" == 0* && ${#n1} -gt 1 ]]; do n1="${n1#0}"; done
        while [[ "$n2" == 0* && ${#n2} -gt 1 ]]; do n2="${n2#0}"; done
        if (( ${#n1} < ${#n2} )); then COMPARE_RESULT="-1"; return; fi
        if (( ${#n1} > ${#n2} )); then COMPARE_RESULT="1"; return; fi
        if [[ "$n1" < "$n2" ]]; then COMPARE_RESULT="-1"; return; fi
        if [[ "$n1" > "$n2" ]]; then COMPARE_RESULT="1"; return; fi
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
            while [[ "$id1" == 0* && ${#id1} -gt 1 ]]; do id1="${id1#0}"; done
            while [[ "$id2" == 0* && ${#id2} -gt 1 ]]; do id2="${id2#0}"; done
            if (( ${#id1} < ${#id2} )); then COMPARE_RESULT="-1"; return; fi
            if (( ${#id1} > ${#id2} )); then COMPARE_RESULT="1"; return; fi
            if [[ "$id1" < "$id2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$id1" > "$id2" ]]; then COMPARE_RESULT="1"; return; fi
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

# Convert one semver shorthand token (~ and ^, full or partial) into its
# comparator pair. Sets EXPANDED_RANGE (no subshell: called per distinct range).
# ~1.2.3 -> >=1.2.3 <1.3.0     ~1.2 -> >=1.2.0 <1.3.0     ~1 -> >=1.0.0 <2.0.0
# ^1.2.3 -> >=1.2.3 <2.0.0     ^0.2 -> >=0.2.0 <0.3.0     ^1 -> >=1.0.0 <2.0.0
# Anything else is returned unchanged.
expand_semver_range() {
    local range="$1"
    EXPANDED_RANGE="$range"
    [[ "$range" =~ ^([~^])([0-9]+)(\.([0-9]+))?(\.([0-9]+))?(.*)$ ]] || return 0
    local op="${BASH_REMATCH[1]}" major="${BASH_REMATCH[2]}"
    local minor="${BASH_REMATCH[4]}" patch="${BASH_REMATCH[6]}" tail="${BASH_REMATCH[7]}"
    # A partial version cannot carry a pre-release tail (~1.2-beta is not semver).
    if [ -n "$tail" ] && [ -z "$patch" ]; then return 0; fi
    local lower="$major.${minor:-0}.${patch:-0}$tail"

    if [ "$op" = "~" ]; then
        if [ -z "$minor" ]; then
            EXPANDED_RANGE=">=$lower <$((major + 1)).0.0"
        else
            EXPANDED_RANGE=">=$lower <$major.$((minor + 1)).0"
        fi
    elif [ "$major" != 0 ] || [ -z "$minor" ]; then
        EXPANDED_RANGE=">=$lower <$((major + 1)).0.0"
    elif [ "$minor" != 0 ] || [ -z "$patch" ]; then
        EXPANDED_RANGE=">=$lower <0.$((minor + 1)).0"
    else
        EXPANDED_RANGE=">=$lower <0.0.$((patch + 1))"
    fi
}

# Parsed form of every distinct range string seen so far: "op ver op ver ..."
# ("*" matches everything, "!" never matches). Ranges repeat across thousands of
# lockfile entries, so normalization runs once per distinct string.
declare -A RANGE_CACHE=()

# Normalize one range (no "||") into RANGE_CACHE. Custom sources write ranges in
# many dialects: ">=1.0,<2.0", ">= 1.0", "==1.0", "=1.0", "^1", "~1.2".
_prepare_range() {
    local raw="$1" r="$1" token op ver parsed="" bad=""
    r="${r//,/ }"
    # Glue a detached operator to its version: ">= 1.0" -> ">=1.0".
    while [[ "$r" =~ ^(.*)(\>=|\<=|==|\>|\<|=|\^|~)[[:space:]]+(.*)$ ]]; do
        r="${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
    done
    local -a tokens
    read -ra tokens <<< "$r"
    if [ "${#tokens[@]}" -eq 1 ] && [ "${tokens[0]}" = "*" ]; then
        RANGE_CACHE["$raw"]="*"
        return
    fi
    local expanded=""
    for token in "${tokens[@]}"; do
        case "$token" in
            "~"*|"^"*) expand_semver_range "$token"; expanded+="$EXPANDED_RANGE " ;;
            *) expanded+="$token " ;;
        esac
    done
    read -ra tokens <<< "$expanded"
    for token in "${tokens[@]}"; do
        if [[ "$token" =~ ^(\>=|\<=|==|\>|\<|=)(.+)$ ]]; then
            op="${BASH_REMATCH[1]}" ver="${BASH_REMATCH[2]}"
            [ "$op" = "==" ] && op="="
        elif [[ "$token" =~ ^[vV]?[0-9] ]]; then
            op="=" ver="$token"     # a bare version is an exact constraint
        else
            bad="$token"; break
        fi
        parsed+="$op $ver "
    done
    if [ -n "$bad" ] || [ -z "$parsed" ]; then
        RANGE_CACHE["$raw"]="!"
        [ -n "$raw" ] && echo -e "${YELLOW}⚠️  Warning: unsupported version range '$raw' (token '$bad'); it never matches${NC}" >&2
        return
    fi
    RANGE_CACHE["$raw"]="${parsed% }"
}

# Check if a version is within a range
# Range format: ">1.0.0 <=2.0.0" or ">=1.0.0 <2.0.0" etc.
# Pre-release versions are included if their base version is within the range
version_in_range() {
    local version="$1"
    local range="$2"

    # Split alternatives before expanding shorthand; otherwise the upper bound
    # generated for the first caret branch is attached to the last branch.
    if [[ "$range" == *"||"* ]]; then
        version_in_range "$version" "${range%%||*}" && return 0
        version_in_range "$version" "${range#*||}"
        return $?
    fi
    range="${range#"${range%%[![:space:]]*}"}"
    range="${range%"${range##*[![:space:]]}"}"

    # Guard against empty range (should not match any version)
    if [ -z "$range" ]; then
        return 1
    fi
    [ "$range" = "*" ] && return 0
    [ -n "${RANGE_CACHE[$range]+x}" ] || _prepare_range "$range"
    local parsed="${RANGE_CACHE[$range]}"
    [ "$parsed" = "*" ] && return 0
    [ "$parsed" = "!" ] && return 1

    # Get base version for pre-release handling
    local base_version="${version%%-*}"
    base_version="${base_version%%+*}"
    local is_prerelease=false
    if [ "$version" != "$base_version" ]; then
        is_prerelease=true
    fi

    local -a conditions
    read -ra conditions <<< "$parsed"
    local idx operator range_version

    for (( idx = 0; idx < ${#conditions[@]}; idx += 2 )); do
        operator="${conditions[$idx]}"
        range_version="${conditions[$((idx + 1))]}"

        # ">=0" admits every version, including pre-releases of 0.0.0 such as
        # Go pseudo-versions (0.0.0-2021...) and npm 0.0.0-experimental builds.
        if [ "$operator" = ">=" ] && [[ "$range_version" =~ ^[vV]?0(\.0)*$ ]]; then
            continue
        fi
        # Identical strings compare equal under every ecosystem comparator.
        if [ "$version" = "$range_version" ]; then
            COMPARE_RESULT=0
        # For pre-release versions, use base version for comparison
        # This allows 19.0.0-rc.1 to be considered as within >=19.0.0
        # OPTIMIZED: dispatch on CHECK_ECO and use COMPARE_RESULT (avoids subshell).
        # npm/everything-else routes to the shared semver comparator; only
        # ecosystems with their own comparator (e.g. golang) diverge.
        elif [ "$is_prerelease" = true ] && [ "${CHECK_ECO:-npm}" = npm ]; then
            # Special handling for >= operator with pre-release
            # 19.0.0-rc is considered >= 19.0.0 (it's a pre-release OF 19.0.0)
            if [ "$operator" = ">=" ] && [ "$base_version" = "$range_version" ]; then
                COMPARE_RESULT="0"  # Consider it equal for >= comparison
            else
                compare_versions_eco "${CHECK_ECO:-npm}" "$version" "$range_version"
            fi
        else
            compare_versions_eco "${CHECK_ECO:-npm}" "$version" "$range_version"
        fi

        case "$operator" in
            "=")
                [ "$COMPARE_RESULT" = "0" ] || return 1
                ;;
            ">")
                if [ "$COMPARE_RESULT" != "1" ]; then
                    return 1  # version is not > range_version
                fi
                ;;
            ">=")
                if [ "$COMPARE_RESULT" = "-1" ]; then
                    return 1  # version is < range_version
                fi
                ;;
            "<")
                if [ "$COMPARE_RESULT" != "-1" ]; then
                    return 1  # version is not < range_version
                fi
                ;;
            "<=")
                if [ "$COMPARE_RESULT" = "1" ]; then
                    return 1  # version is > range_version
                fi
                ;;
        esac
    done
    return 0
}

# Check if a version matches a vulnerable version (exact or pre-release of it)
version_matches_vulnerable() {
    local installed_version="$1"
    local versions="$2"
    
    # Exact match
    if [ "$installed_version" = "$versions" ]; then
        return 0
    fi

    # Other ecosystems use their own version equality. npm retains the
    # historical conservative prerelease-of-exact matching policy below.
    if [ "${CHECK_ECO:-npm}" != npm ]; then
        compare_versions_eco "$CHECK_ECO" "$installed_version" "$versions"
        [ "$COMPARE_RESULT" = 0 ]
        return $?
    fi
    
    # Check if installed version is a pre-release of the vulnerable version
    # For example: "19.0.0-rc-xxx" should match "19.0.0"
    local installed_base="${installed_version%%-*}"
    installed_base="${installed_base%%+*}"
    
    if [ "$installed_base" = "$versions" ] && [ "$installed_version" != "$installed_base" ]; then
        # It's a pre-release version (has suffix) and base matches
        return 0
    fi
    
    return 1
}
