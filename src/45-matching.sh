build_vulnerability_lookup() {
    if [ "$VULN_LOOKUP_BUILT" = true ]; then
        return 0
    fi

    # NOTE: Do NOT clear existing data - we want to merge with CSV data if present
    # VULN_EXACT_LOOKUP=()
    # VULN_RANGE_LOOKUP=()
    
    # Use awk to parse JSON and generate bash eval statements directly
    # This avoids the slow while-read loop in bash
    local eval_commands
    eval_commands=$(echo "$VULN_DATA" | awk '
    BEGIN {
        pkg = ""
        in_ver = 0
        in_range = 0
    }
    
    # Function to escape single quotes for bash
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }
    
    {
        # Work character by character to handle JSON properly
        line = $0
        n = length(line)
        
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            
            # Simple state machine
            if (c == "\"") {
                # Start of quoted string - find the end
                start = i + 1
                i++
                while (i <= n) {
                    c2 = substr(line, i, 1)
                    if (c2 == "\\") {
                        i++  # Skip escaped char
                    } else if (c2 == "\"") {
                        break
                    }
                    i++
                }
                end = i - 1
                str = substr(line, start, end - start + 1)
                
                # Check what comes after the string
                rest = substr(line, i + 1)
                if (match(rest, /^[[:space:]]*:[[:space:]]*\{/)) {
                    # This is a package name
                    pkg = str
                    in_ver = 0
                    in_range = 0
                } else if (str == "versions" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
                    in_ver = 1
                    in_range = 0
                } else if (str == "versions_range" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
                    in_range = 1
                    in_ver = 0
                } else if (in_ver && pkg != "" && str != "") {
                    # Aggregate exact versions by package
                    if (pkg in exact_vers) {
                        exact_vers[pkg] = exact_vers[pkg] "|" str
                    } else {
                        exact_vers[pkg] = str
                    }
                } else if (in_range && pkg != "" && str != "") {
                    # Aggregate ranges by package
                    if (pkg in range_vers) {
                        range_vers[pkg] = range_vers[pkg] "|" str
                    } else {
                        range_vers[pkg] = str
                    }
                }
            } else if (c == "]") {
                in_ver = 0
                in_range = 0
            }
        }
    }
    END {
        # JSON sources carry no ecosystem info -> wildcard namespace "*:"
        # Output bash eval statements that MERGE with existing data
        for (pkg in exact_vers) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(exact_vers[pkg]), escape_sq(nk), escape_sq(exact_vers[pkg])
        }
        for (pkg in range_vers) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(range_vers[pkg]), escape_sq(nk), escape_sq(range_vers[pkg])
        }
    }
    ')

    # Execute all assignments at once (much faster than while-read loop)
    eval "$eval_commands"
    
    VULN_LOOKUP_BUILT=true
}

# Function to check if a package+version is vulnerable
# Uses pre-built lookup tables for O(1) access
# Reports ALL matching advisories (not just the first)
#
# Args: eco name version source_file
# Probes BOTH the ecosystem namespace (eco:name) and the wildcard namespace
# (*:name) so that ecosystem-tagged feeds and ecosystem-agnostic feeds
# (CSV/JSON/SARIF) both match, without cross-ecosystem collisions.
check_vulnerability() {
    local eco="$1"
    local name="$2"
    local version="$3"
    local source="$4"

    # Forward wiring: later tasks dispatch version comparators on the ecosystem.
    CHECK_ECO="$eco"

    # Candidate lookup keys: ecosystem namespace first, then wildcard.
    local -a probe_keys=("${eco}:${name}")
    if [ "$eco" != "*" ]; then
        probe_keys+=("*:${name}")
    fi

    # Fast existence check across all probes (O(1) each)
    local any_exists=false
    local pk
    for pk in "${probe_keys[@]}"; do
        if [ -n "${VULN_EXACT_LOOKUP[$pk]+x}" ] || [ -n "${VULN_RANGE_LOOKUP[$pk]+x}" ]; then
            any_exists=true
            break
        fi
    done
    [ "$any_exists" = false ] && return 1

    # Advisories are grouped/looked up under the SCANNED package's namespace.
    local exact_meta_key="${eco}:${name}@${version}"
    local found=false
    local first_match_msg=""

    # Skip metadata collection if already done for this package@version (called from another file)
    local already_checked=false
    if [ -n "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
        already_checked=true
    fi

    # Track seen GHSA IDs for deduplication across BOTH namespaces
    declare -A _seen_ghsas

    for pk in "${probe_keys[@]}"; do
        # Get vulnerable versions/ranges stored under this namespaced key
        local vulnerability_versions="${VULN_EXACT_LOOKUP[$pk]:-}"
        local vulnerability_ranges="${VULN_RANGE_LOOKUP[$pk]:-}"

        # Check exact version matches
        if [ -n "$vulnerability_versions" ]; then
            IFS='|' read -ra vers_array <<< "$vulnerability_versions"
            for vulnerability_ver in "${vers_array[@]}"; do
                [ -z "$vulnerability_ver" ] && continue
                if version_matches_vulnerable "$version" "$vulnerability_ver"; then
                    if [ "$found" = false ]; then
                        if [ "$version" = "$vulnerability_ver" ]; then
                            first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable)${NC}"
                        else
                            first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable - pre-release of $vulnerability_ver)${NC}"
                        fi
                    fi
                    if [ "$already_checked" = false ]; then
                        local ver_meta_key="${pk}@${vulnerability_ver}"
                        local sev="${VULN_METADATA_SEVERITY[$ver_meta_key]:-}"
                        local ghsa="${VULN_METADATA_GHSA[$ver_meta_key]:-}"
                        local cve="${VULN_METADATA_CVE[$ver_meta_key]:-}"
                        local msrc="${VULN_METADATA_SOURCE[$ver_meta_key]:-}"
                        local fix="${VULN_METADATA_FIX[$ver_meta_key]:-}"
                        # Cross-namespace dedup: skip if this advisory (GHSA) already recorded
                        if [ -n "$ghsa" ] && [ -n "${_seen_ghsas[$ghsa]+x}" ]; then
                            found=true
                            continue
                        fi
                        [ -n "$ghsa" ] && _seen_ghsas[$ghsa]=1
                        local advisory_entry="${sev};${ghsa};${cve};${msrc};${fix}"
                        if [ -z "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
                            VULN_ADVISORIES[$exact_meta_key]="$advisory_entry"
                        else
                            VULN_ADVISORIES[$exact_meta_key]+="||${advisory_entry}"
                        fi
                        # Set VULN_METADATA_* for first match (backward compat with exports)
                        if [ -z "${VULN_METADATA_SEVERITY[$exact_meta_key]+x}" ]; then
                            [ -n "$sev" ] && VULN_METADATA_SEVERITY[$exact_meta_key]="$sev"
                            [ -n "$ghsa" ] && VULN_METADATA_GHSA[$exact_meta_key]="$ghsa"
                            [ -n "$cve" ] && VULN_METADATA_CVE[$exact_meta_key]="$cve"
                            [ -n "$msrc" ] && VULN_METADATA_SOURCE[$exact_meta_key]="$msrc"
                        fi
                    fi
                    found=true
                fi
            done
        fi

        # Check version ranges - check ALL ranges to report all matching advisories
        # Deduplicate by GHSA ID and skip matches where version is already patched
        if [ -n "$vulnerability_ranges" ]; then
            IFS='|' read -ra ranges_array <<< "$vulnerability_ranges"
            for range in "${ranges_array[@]}"; do
                [ -z "$range" ] && continue
                if version_in_range "$version" "$range"; then
                    local range_meta_key="${pk}:${range}"
                    local ghsa="${VULN_METADATA_GHSA[$range_meta_key]:-}"

                    # Skip if version is patched for this GHSA (version >= highest upper bound)
                    if [ -n "$ghsa" ]; then
                        local patched_key="${pk}:${ghsa}"
                        if [ -n "${VULN_PATCHED[$patched_key]+x}" ]; then
                            local patched_ver="${VULN_PATCHED[$patched_key]}"
                            compare_versions "$version" "$patched_ver"
                            if [ "$COMPARE_RESULT" != "-1" ]; then
                                # Version >= patched version, not vulnerable for this GHSA
                                continue
                            fi
                        fi
                    fi

                    # Deduplicate by GHSA ID (across both namespaces)
                    if [ -n "$ghsa" ]; then
                        if [ -n "${_seen_ghsas[$ghsa]+x}" ]; then
                            continue
                        fi
                        _seen_ghsas[$ghsa]=1
                    fi

                    if [ "$found" = false ]; then
                        first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable - matches range: $range)${NC}"
                    fi
                    if [ "$already_checked" = false ]; then
                        local sev="${VULN_METADATA_SEVERITY[$range_meta_key]:-}"
                        local cve="${VULN_METADATA_CVE[$range_meta_key]:-}"
                        local msrc="${VULN_METADATA_SOURCE[$range_meta_key]:-}"
                        local fix="${VULN_METADATA_FIX[$range_meta_key]:-}"
                        local advisory_entry="${sev};${ghsa};${cve};${msrc};${fix}"
                        if [ -z "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
                            VULN_ADVISORIES[$exact_meta_key]="$advisory_entry"
                        else
                            VULN_ADVISORIES[$exact_meta_key]+="||${advisory_entry}"
                        fi
                        # Set VULN_METADATA_* for first match (backward compat with exports)
                        if [ -z "${VULN_METADATA_SEVERITY[$exact_meta_key]+x}" ]; then
                            [ -n "$sev" ] && VULN_METADATA_SEVERITY[$exact_meta_key]="$sev"
                            [ -n "$ghsa" ] && VULN_METADATA_GHSA[$exact_meta_key]="$ghsa"
                            [ -n "$cve" ] && VULN_METADATA_CVE[$exact_meta_key]="$cve"
                            [ -n "$msrc" ] && VULN_METADATA_SOURCE[$exact_meta_key]="$msrc"
                        fi
                    fi
                    found=true
                fi
            done
        fi
    done
    unset _seen_ghsas

    if [ "$found" = true ]; then
        echo -e "$first_match_msg"
        FOUND_VULNERABLE=1
        VULNERABLE_PACKAGES+=("$source|$eco|$name@$version")
        return 0
    fi

    # Package is in the list but installed version is not vulnerable
    # Silently return to avoid spamming output for large vulnerability databases
    return 1
}

# Function to analyze a package-lock.json file
# Optimized: uses awk for batch extraction instead of JSON parsing loops
# Uses POSIX-compatible awk syntax for macOS compatibility
