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

# Convert semver ranges (~ and ^) to standard range format
# ~1.2.3 -> >=1.2.3 <1.3.0
# ^1.2.3 -> >=1.2.3 <2.0.0
expand_semver_range() {
    local range="$1"

    # Handle tilde ranges: ~1.2.3 means >=1.2.3 <1.3.0
    if [[ "$range" =~ ^~([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"
        local prerelease="${BASH_REMATCH[4]}"
        local next_minor=$((minor + 1))
        echo ">=$major.$minor.$patch$prerelease <$major.$next_minor.0"
        return 0
    fi

    # Handle caret ranges: ^1.2.3 means >=1.2.3 <2.0.0
    if [[ "$range" =~ ^\^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"
        local prerelease="${BASH_REMATCH[4]}"

        # For ^0.x.y, it's more restrictive
        if [ "$major" = "0" ]; then
            if [ "$minor" = "0" ]; then
                # ^0.0.x -> >=0.0.x <0.0.(x+1)
                local next_patch=$((patch + 1))
                echo ">=$major.$minor.$patch$prerelease <$major.$minor.$next_patch"
            else
                # ^0.x.y -> >=0.x.y <0.(x+1).0
                local next_minor=$((minor + 1))
                echo ">=$major.$minor.$patch$prerelease <$major.$next_minor.0"
            fi
        else
            # ^x.y.z -> >=x.y.z <(x+1).0.0
            local next_major=$((major + 1))
            echo ">=$major.$minor.$patch$prerelease <$next_major.0.0"
        fi
        return 0
    fi

    # Return original if no semver range detected
    echo "$range"
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
    case "$range" in "~"*|"^"*) range=$(expand_semver_range "$range") ;; esac

    # Guard against empty range (should not match any version)
    if [ -z "$range" ]; then
        return 1
    fi

    # Get base version for pre-release handling
    local base_version="${version%%-*}"
    base_version="${base_version%%+*}"
    local is_prerelease=false
    if [ "$version" != "$base_version" ]; then
        is_prerelease=true
    fi
    
    # Parse the range - split by space
    [[ "$range" =~ ^[[:space:]]*\*[[:space:]]*$ ]] && return 0
    local -a conditions
    read -ra conditions <<< "$range"
    local valid=false
    
    for condition in "${conditions[@]}"; do
        local operator=""
        local range_version=""
        
        # Extract operator and version
        if [[ "$condition" =~ ^(\>=|\<=|\>|\<)(.+)$ ]]; then
            operator="${BASH_REMATCH[1]}"
            range_version="${BASH_REMATCH[2]}"
        else
            # A bare version is an exact constraint; reject unsupported tokens.
            if [[ "$condition" =~ ^[0-9] ]]; then
                operator="="
                range_version="$condition"
            else
                return 1
            fi
        fi
        
        # For pre-release versions, use base version for comparison
        # This allows 19.0.0-rc.1 to be considered as within >=19.0.0
        # OPTIMIZED: dispatch on CHECK_ECO and use COMPARE_RESULT (avoids subshell).
        # npm/everything-else routes to the shared semver comparator; only
        # ecosystems with their own comparator (e.g. golang) diverge.
        if [ "$is_prerelease" = true ] && [ "${CHECK_ECO:-npm}" = npm ]; then
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

        valid=true
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
    
    [ "$valid" = true ]  # Empty/invalid conditions must not match everything.
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

# Build vulnerability lookup tables from VULN_DATA for O(1) lookups
# This parses the JSON once and stores in associative arrays
# OPTIMIZED: awk generates bash eval statements directly, avoiding slow bash loops
# NOTE: This function MERGES JSON data with existing lookup tables (e.g., from CSV)
