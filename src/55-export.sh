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

# Shared legacy metadata projection: one row per package occurrence.
export_metadata() {
    local eco="$1" pkg="$2"
    local key="${eco}:${pkg}" name="${pkg%@*}"
    severity="${VULN_METADATA_SEVERITY[$key]:-${VULN_METADATA_SEVERITY[$name]:-}}"
    ghsa="${VULN_METADATA_GHSA[$key]:-${VULN_METADATA_GHSA[$name]:-}}"
    cve="${VULN_METADATA_CVE[$key]:-${VULN_METADATA_CVE[$name]:-}}"
    source="${VULN_METADATA_SOURCE[$key]:-${VULN_METADATA_SOURCE[$name]:-}}"
}

export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"
    local vuln file eco pkg severity ghsa cve source field first=true
    local -A unique=()
    {
        printf '{\n  "vulnerabilities": [\n'
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            unique["${eco}:${pkg}"]=1
            if [ "$first" = true ]; then first=false; else printf ',\n'; fi
            export_metadata "$eco" "$pkg"
            printf '    {"package": '; json_print_string "$pkg"
            printf ', "file": '; json_print_string "$file"
            printf ', "ecosystem": '; json_print_string "$eco"
            for field in severity ghsa cve source; do
                if [ -n "${!field}" ]; then
                    printf ', "%s": ' "$field"
                    json_print_string "${!field}"
                fi
            done
            printf '}'
        done
        printf '\n  ],\n  "summary": {\n'
        printf '    "total_unique_vulnerabilities": %s,\n' "${#unique[@]}"
        printf '    "total_occurrences": %s\n' "${#VULNERABLE_PACKAGES[@]}"
        printf '  }\n}\n'
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"
    local vuln file eco pkg severity ghsa cve source value first
    {
        printf 'package,file,severity,ghsa,cve,source,ecosystem\n'
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            export_metadata "$eco" "$pkg"
            first=true
            for value in "$pkg" "$file" "$severity" "$ghsa" "$cve" "$source" "$eco"; do
                if [ "$first" = true ]; then first=false; else printf ','; fi
                printf '"%s"' "${value//\"/\"\"}"
            done
            printf '\n'
        done
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ CSV report exported to: $output_file${NC}"
}
