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
    local v1="$1"
    local v2="$2"

    # Extract base versions for comparison (optimized with parameter expansion)
    local base1="${v1%%-*}"
    base1="${base1%%+*}"  # Strip build metadata (+build123)
    local base2="${v2%%-*}"
    base2="${base2%%+*}"

    # Split into major.minor.patch using parameter expansion (faster than cut/awk)
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)

    local major1="${parts1[0]:-0}"
    local minor1="${parts1[1]:-0}"
    local patch1="${parts1[2]:-0}"

    local major2="${parts2[0]:-0}"
    local minor2="${parts2[1]:-0}"
    local patch2="${parts2[2]:-0}"

    # Default to 0 if empty
    major1=${major1:-0}
    minor1=${minor1:-0}
    patch1=${patch1:-0}
    major2=${major2:-0}
    minor2=${minor2:-0}
    patch2=${patch2:-0}

    # Compare major
    if [ "$major1" -lt "$major2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$major1" -gt "$major2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Compare minor
    if [ "$minor1" -lt "$minor2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$minor1" -gt "$minor2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Compare patch
    if [ "$patch1" -lt "$patch2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$patch1" -gt "$patch2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Base versions are equal, check pre-release
    # Pre-release versions have lower precedence than normal versions
    local has_prerelease1=false
    local has_prerelease2=false

    if [ "$v1" != "$base1" ]; then
        has_prerelease1=true
    fi
    if [ "$v2" != "$base2" ]; then
        has_prerelease2=true
    fi

    # If one has pre-release and other doesn't
    if [ "$has_prerelease1" = true ] && [ "$has_prerelease2" = false ]; then
        COMPARE_RESULT="-1"  # pre-release < release
        return
    elif [ "$has_prerelease1" = false ] && [ "$has_prerelease2" = true ]; then
        COMPARE_RESULT="1"   # release > pre-release
        return
    fi

    # Both have pre-release: compare pre-release identifiers lexicographically
    # Handles common patterns: alpha < beta < rc, canary.1 < canary.2
    if [ "$has_prerelease1" = true ] && [ "$has_prerelease2" = true ]; then
        local pre1="${v1#*-}"
        local pre2="${v2#*-}"
        # Strip build metadata from pre-release part
        pre1="${pre1%%+*}"
        pre2="${pre2%%+*}"
        if [[ "$pre1" < "$pre2" ]]; then
            COMPARE_RESULT="-1"
            return
        elif [[ "$pre1" > "$pre2" ]]; then
            COMPARE_RESULT="1"
            return
        fi
    fi

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

    # Expand semver ranges first
    range=$(expand_semver_range "$range")

    # Guard against empty range (should not match any version)
    if [ -z "$range" ]; then
        return 1
    fi

    # Get base version for pre-release handling
    local base_version=$(get_base_version "$version")
    local is_prerelease=false
    if [ "$version" != "$base_version" ]; then
        is_prerelease=true
    fi
    
    # Parse the range - split by space
    local conditions=($range)
    
    for condition in "${conditions[@]}"; do
        local operator=""
        local range_version=""
        
        # Extract operator and version
        if [[ "$condition" =~ ^(\>=|\<=|\>|\<)(.+)$ ]]; then
            operator="${BASH_REMATCH[1]}"
            range_version="${BASH_REMATCH[2]}"
        else
            # No operator, skip invalid condition
            continue
        fi
        
        # For pre-release versions, use base version for comparison
        # This allows 19.0.0-rc.1 to be considered as within >=19.0.0
        # OPTIMIZED: Call compare_versions directly and use COMPARE_RESULT (avoids subshell)
        if [ "$is_prerelease" = true ]; then
            # Special handling for >= operator with pre-release
            # 19.0.0-rc is considered >= 19.0.0 (it's a pre-release OF 19.0.0)
            if [ "$operator" = ">=" ] && [ "$base_version" = "$range_version" ]; then
                COMPARE_RESULT="0"  # Consider it equal for >= comparison
            else
                compare_versions "$version" "$range_version"
            fi
        else
            compare_versions "$version" "$range_version"
        fi

        case "$operator" in
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
    
    return 0  # All conditions passed
}

# Check if a version matches a vulnerable version (exact or pre-release of it)
version_matches_vulnerable() {
    local installed_version="$1"
    local versions="$2"
    
    # Exact match
    if [ "$installed_version" = "$versions" ]; then
        return 0
    fi
    
    # Check if installed version is a pre-release of the vulnerable version
    # For example: "19.0.0-rc-xxx" should match "19.0.0"
    local installed_base=$(get_base_version "$installed_version")
    
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
