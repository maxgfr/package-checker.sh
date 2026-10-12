# Severity rank used to compare and count advisories (sets SEV_RANK).
# GHSA spells medium "moderate".
severity_rank() {
    case "${1,,}" in
        critical) SEV_RANK=4 ;;
        high) SEV_RANK=3 ;;
        medium|moderate) SEV_RANK=2 ;;
        low) SEV_RANK=1 ;;
        *) SEV_RANK=0 ;;
    esac
}

# Collect the advisories attached to a matched version/range into the
# caller's adv_list (records "severity;ghsa;cve;source;fix;id") and adv_ids
# (identity -> index). GHSA and OSV describe the same advisory in two records:
# records sharing a GHSA id, a CVE or an OSV id merge into one entry whose
# sources accumulate ("ghsa, osv") and whose missing fields are filled in.
# Two different GHSA ids never merge.
record_matching_advisories() {
    local lookup_key="$1"
    local records="${VULN_RECORDS[$lookup_key]:-}"
    local record severity ghsa cve source fix id idx key
    local s0 g0 c0 src0 f0 i0
    [ -n "$records" ] || records=";;;;;"
    while IFS= read -r record; do
        [ -n "$record" ] || continue
        IFS=';' read -r severity ghsa cve source fix id <<< "$record"
        idx=""
        if [ -n "$ghsa$cve$id" ]; then
            for key in ${ghsa:+"ghsa:$ghsa"} ${cve:+"cve:$cve"} ${id:+"id:$id"}; do
                [ -n "${adv_ids[$key]+x}" ] || continue
                idx="${adv_ids[$key]}"
                IFS=';' read -r s0 g0 c0 src0 f0 i0 <<< "${adv_list[$idx]}"
                if [ -n "$ghsa" ] && [ -n "$g0" ] && [ "$ghsa" != "$g0" ]; then
                    idx=""
                    continue
                fi
                break
            done
        elif [ -n "${adv_ids[record:$record]+x}" ]; then
            continue
        fi
        if [ -z "$idx" ]; then
            idx=${#adv_list[@]}
            adv_list+=("$record")
            [ -n "$ghsa$cve$id" ] || adv_ids["record:$record"]="$idx"
        else
            IFS=';' read -r s0 g0 c0 src0 f0 i0 <<< "${adv_list[$idx]}"
            severity_rank "$s0"; local rank0=$SEV_RANK
            severity_rank "$severity"
            [ "$SEV_RANK" -gt "$rank0" ] || severity="$s0"
            case ", $src0, " in
                *", $source, "*) source="$src0" ;;
                *) source="${src0:+$src0${source:+, }}$source" ;;
            esac
            adv_list[$idx]="$severity;${g0:-$ghsa};${c0:-$cve};$source;${f0:-$fix};${i0:-$id}"
            IFS=';' read -r severity ghsa cve source fix id <<< "${adv_list[$idx]}"
        fi
        for key in ${ghsa:+"ghsa:$ghsa"} ${cve:+"cve:$cve"} ${id:+"id:$id"}; do
            adv_ids["$key"]="$idx"
        done
    done <<< "$records"
}

# Store the merged advisories of one finding. VULN_ADVISORIES keeps them all
# ("rec||rec"); the VULN_METADATA_* summary uses the most severe advisory and
# VULN_METADATA_FIX the highest fixed version (the one that fixes them all).
finalize_advisories() {
    local result_key="$1" rec joined="" best="" best_rank=-1 fixed=""
    local severity ghsa cve source fix id
    for rec in "${adv_list[@]}"; do
        joined+="${joined:+||}$rec"
        IFS=';' read -r severity ghsa cve source fix id <<< "$rec"
        severity_rank "$severity"
        if [ "$SEV_RANK" -gt "$best_rank" ]; then best_rank=$SEV_RANK; best="$rec"; fi
        if [ -n "$fix" ]; then
            if [ -z "$fixed" ]; then
                fixed="$fix"
            else
                compare_versions_eco "$CHECK_ECO" "$fix" "$fixed"
                [ "$COMPARE_RESULT" != 1 ] || fixed="$fix"
            fi
        fi
    done
    VULN_ADVISORIES["$result_key"]="$joined"
    IFS=';' read -r severity ghsa cve source fix id <<< "$best"
    VULN_METADATA_SEVERITY["$result_key"]="$severity"
    VULN_METADATA_GHSA["$result_key"]="$ghsa"
    VULN_METADATA_CVE["$result_key"]="$cve"
    VULN_METADATA_SOURCE["$result_key"]="$source"
    VULN_METADATA_FIX["$result_key"]="$fixed"
}

# Canonical form of a user-supplied package name for an ecosystem (the form
# the lockfile parsers and feeds use). Sets CANON_NAME.
canonical_package_name() {
    case "$1" in
        pypi) _pypi_normalize_name "$2"; CANON_NAME="$PEP503_NAME" ;;
        nuget|composer|githubactions) CANON_NAME="${2,,}" ;;
        swift)
            local n="${2,,}"
            n="${n#*://}"; n="${n%/}"; n="${n%.git}"
            CANON_NAME="$n" ;;
        *) CANON_NAME="$2" ;;
    esac
}

# Probe ecosystem-specific and wildcard feeds without cross-ecosystem leakage.
# Args: ecosystem package version source-file. With --package-name, only that
# package (PACKAGE_FILTER = "eco:name") is reported.
check_vulnerability() {
    local eco="$1" name="$2" version="$3" source="$4"
    if [ -n "${PACKAGE_FILTER:-}" ] && [ "$eco:$name" != "$PACKAGE_FILTER" ]; then
        return 1
    fi
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
    local -A seen_candidates=() adv_ids=()
    local -a adv_list=()
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
                    record_matching_advisories "$lookup_key"
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
                    record_matching_advisories "$lookup_key"
                fi
            fi
        done <<< "${VULN_RANGE_LOOKUP[$pk]:-}"
    done

    if [ "$found" = true ]; then
        [ "$collect" = false ] || finalize_advisories "$result_key"
        echo -e "${RED}⚠️  [$source] $name@$version $message${NC}"
        FOUND_VULNERABLE=1
        VULNERABLE_PACKAGES+=("$source|$eco|$name@$version")
        return 0
    fi
    return 1
}
