# Write a JSON string without a subshell or a runtime JSON dependency.
json_print_string() {
    local value="$1" code char escaped
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    if [[ "$value" == *[$'\001'-$'\037']* ]]; then
        for ((code = 1; code < 32; code++)); do
            printf -v escaped '\\%03o' "$code"
            printf -v char '%b' "$escaped"
            printf -v escaped '\\u%04x' "$code"
            value="${value//"$char"/"$escaped"}"
        done
    fi
    printf '"%s"' "$value"
}

# Summary metadata of one finding: the most severe advisory's fields, the
# version that fixes every advisory (see finalize_advisories) and, with
# --go-reachability, whether the code calls it.
export_metadata() {
    local eco="$1" pkg="$2"
    local key="${eco}:${pkg}" name="${pkg%@*}"
    severity="${VULN_METADATA_SEVERITY[$key]:-${VULN_METADATA_SEVERITY[$name]:-}}"
    ghsa="${VULN_METADATA_GHSA[$key]:-${VULN_METADATA_GHSA[$name]:-}}"
    cve="${VULN_METADATA_CVE[$key]:-${VULN_METADATA_CVE[$name]:-}}"
    source="${VULN_METADATA_SOURCE[$key]:-${VULN_METADATA_SOURCE[$name]:-}}"
    fixed_in="${VULN_METADATA_FIX[$key]:-}"
    reachability="${VULN_REACHABILITY[$key]:-}"
}

# The report is written even when nothing is vulnerable, so a CI job never
# picks up a stale report from an earlier run.
export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"
    local vuln file eco pkg severity ghsa cve source fixed_in reachability field first=true
    local advisories advisory a_first a_sev a_ghsa a_cve a_source a_fix a_id
    local -A unique=()
    {
        printf '{\n  "vulnerabilities": ['
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            unique["${eco}:${pkg}"]=1
            if [ "$first" = true ]; then first=false; printf '\n'; else printf ',\n'; fi
            export_metadata "$eco" "$pkg"
            printf '    {"package": '; json_print_string "$pkg"
            printf ', "name": '; json_print_string "${pkg%@*}"
            printf ', "version": '; json_print_string "${pkg##*@}"
            printf ', "file": '; json_print_string "$file"
            printf ', "ecosystem": '; json_print_string "$eco"
            for field in severity ghsa cve source fixed_in reachability; do
                if [ -n "${!field}" ]; then
                    printf ', "%s": ' "$field"
                    json_print_string "${!field}"
                fi
            done
            printf ', "advisories": ['
            advisories="${VULN_ADVISORIES[$eco:$pkg]:-}"
            a_first=true
            while [ -n "$advisories" ]; do
                advisory="${advisories%%||*}"
                if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
                IFS=';' read -r a_sev a_ghsa a_cve a_source a_fix a_id <<< "$advisory"
                [ -n "$a_sev$a_ghsa$a_cve$a_source$a_fix$a_id" ] || continue
                if [ "$a_first" = true ]; then a_first=false; else printf ', '; fi
                printf '{"severity": '; json_print_string "$a_sev"
                printf ', "ghsa": '; json_print_string "$a_ghsa"
                printf ', "cve": '; json_print_string "$a_cve"
                printf ', "id": '; json_print_string "$a_id"
                printf ', "source": '; json_print_string "$a_source"
                printf ', "fix": '; json_print_string "$a_fix"
                printf '}'
            done
            printf ']}'
        done
        [ "$first" = true ] || printf '\n  '
        printf '],\n  "summary": {\n'
        printf '    "total_unique_vulnerabilities": %s,\n' "${#unique[@]}"
        printf '    "total_occurrences": %s\n' "${#VULNERABLE_PACKAGES[@]}"
        printf '  }\n}\n'
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

# Quote one CSV cell. A cell starting with = + - @ (or a tab/CR) is a formula
# in spreadsheet applications: prefix it with an apostrophe.
csv_cell() {
    local value="$1"
    case "$value" in
        [=+@-]*|$'\t'*|$'\r'*) value="'$value" ;;
    esac
    printf '"%s"' "${value//\"/\"\"}"
}

export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"
    local vuln file eco pkg severity ghsa cve source fixed_in reachability value first
    {
        printf 'package,file,severity,ghsa,cve,source,ecosystem,version,fix,reachability\n'
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            export_metadata "$eco" "$pkg"
            first=true
            for value in "$pkg" "$file" "$severity" "$ghsa" "$cve" "$source" "$eco" "${pkg##*@}" "$fixed_in" "$reachability"; do
                if [ "$first" = true ]; then first=false; else printf ','; fi
                csv_cell "$value"
            done
            printf '\n'
        done
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ CSV report exported to: $output_file${NC}"
}
