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
