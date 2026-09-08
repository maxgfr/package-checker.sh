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
                        range_vers[pkg] = range_vers[pkg] "\n" str
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
            printf "VULN_EXACT_LOOKUP['\''%s'\'']+='\''|%s'\''\n", escape_sq(nk), escape_sq(exact_vers[pkg])
        }
        for (pkg in range_vers) {
            nk = "*:" pkg
            printf "VULN_RANGE_LOOKUP['\''%s'\'']+='\''%s\n'\''\n", escape_sq(nk), escape_sq(range_vers[pkg])
        }
    }
    ')

    # Execute all assignments at once (much faster than while-read loop)
    eval "$eval_commands"
    
    VULN_LOOKUP_BUILT=true
}

# Collect all advisories attached to a matched version/range. The caller owns
# the per-package seen set so duplicates across namespaces/sources collapse.
record_matching_advisories() {
    local lookup_key="$1" result_key="$2"
    local records="${VULN_RECORDS[$lookup_key]:-}"
    local record severity ghsa cve source fix identity
    [ -n "$records" ] || records=";;;;"
    while IFS= read -r record; do
        [ -n "$record" ] || continue
        IFS=';' read -r severity ghsa cve source fix <<< "$record"
        if [ -n "$ghsa" ]; then identity="ghsa:$ghsa"
        elif [ -n "$cve" ]; then identity="cve:$cve"
        else identity="record:$record"
        fi
        [ -n "${seen_advisories[$identity]+x}" ] && continue
        seen_advisories["$identity"]=1
        if [ -z "${VULN_ADVISORIES[$result_key]+x}" ]; then
            VULN_ADVISORIES["$result_key"]="$record"
            # Public exports keep the first advisory; console/issues retain all.
            VULN_METADATA_SEVERITY["$result_key"]="$severity"
            VULN_METADATA_GHSA["$result_key"]="$ghsa"
            VULN_METADATA_CVE["$result_key"]="$cve"
            VULN_METADATA_SOURCE["$result_key"]="$source"
            VULN_METADATA_FIX["$result_key"]="$fix"
        else
            VULN_ADVISORIES["$result_key"]+="||$record"
        fi
    done <<< "$records"
}

# Probe ecosystem-specific and wildcard feeds without cross-ecosystem leakage.
# Args: ecosystem package version source-file.
check_vulnerability() {
    local eco="$1" name="$2" version="$3" source="$4"
    # Most installed packages have no advisory. Avoid allocating per-advisory
    # maps and parsing four empty lists for every such dependency in a lockfile.
    if [ -z "${VULN_EXACT_LOOKUP[$eco:$name]+x}" ] &&
        [ -z "${VULN_RANGE_LOOKUP[$eco:$name]+x}" ] &&
        [ -z "${VULN_EXACT_LOOKUP[*:$name]+x}" ] &&
        [ -z "${VULN_RANGE_LOOKUP[*:$name]+x}" ]; then
        return 1
    fi
    CHECK_ECO="$eco"
    local result_key="${eco}:${name}@${version}"
    local -a probe_keys=("${eco}:${name}")
    [ "$eco" = "*" ] || probe_keys+=("*:${name}")
    local pk candidate lookup_key message="" found=false
    local -a candidates
    local -A seen_advisories=() seen_candidates=()
    local collect=true
    [ -z "${VULN_ADVISORIES[$result_key]+x}" ] || collect=false

    for pk in "${probe_keys[@]}"; do
        IFS='|' read -ra candidates <<< "${VULN_EXACT_LOOKUP[$pk]:-}"
        for candidate in "${candidates[@]}"; do
            [ -n "$candidate" ] || continue
            lookup_key="${pk}@${candidate}"
            [ -z "${seen_candidates[$lookup_key]+x}" ] || continue
            seen_candidates["$lookup_key"]=1
            if version_matches_vulnerable "$version" "$candidate"; then
                if [ "$found" = false ]; then
                    if [ "$version" = "$candidate" ]; then
                        message="(vulnerable)"
                    else
                        message="(vulnerable - pre-release of $candidate)"
                    fi
                fi
                found=true
                if [ "$collect" = true ]; then
                    record_matching_advisories "$lookup_key" "$result_key"
                fi
            fi
        done

        # Newlines separate complete ranges, preserving OR (||) expressions.
        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            lookup_key="${pk}:${candidate}"
            [ -z "${seen_candidates[$lookup_key]+x}" ] || continue
            seen_candidates["$lookup_key"]=1
            if version_in_range "$version" "$candidate"; then
                if [ "$found" = false ]; then
                    message="(vulnerable - matches range: $candidate)"
                fi
                found=true
                if [ "$collect" = true ]; then
                    record_matching_advisories "$lookup_key" "$result_key"
                fi
            fi
        done <<< "${VULN_RANGE_LOOKUP[$pk]:-}"
    done

    if [ "$found" = true ]; then
        echo -e "${RED}⚠️  [$source] $name@$version $message${NC}"
        FOUND_VULNERABLE=1
        VULNERABLE_PACKAGES+=("$source|$eco|$name@$version")
        return 0
    fi
    return 1
}
