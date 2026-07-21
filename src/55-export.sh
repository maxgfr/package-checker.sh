export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"

    {
        echo "{"
        echo '  "vulnerabilities": ['

        local first=true
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"

            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi

            echo -n '    {'
            echo -n '"package": "'"$pkg"'", '
            echo -n '"file": "'"$file"'"'
            echo -n ', "ecosystem": "'"$eco"'"'

            # Add metadata if available (namespaced key; fall back to name-only, scoped-safe)
            local meta_key="${eco}:${pkg}"
            local pkg_name_only="${pkg%@*}"
            local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
            local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
            local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
            local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

            if [ -n "$severity" ]; then
                echo -n ', "severity": "'"$severity"'"'
            fi

            if [ -n "$ghsa" ]; then
                echo -n ', "ghsa": "'"$ghsa"'"'
            fi

            if [ -n "$cve" ]; then
                echo -n ', "cve": "'"$cve"'"'
            fi

            if [ -n "$source" ]; then
                echo -n ', "source": "'"$source"'"'
            fi

            echo -n '}'
        done

        echo ""
        echo '  ],'
        echo '  "summary": {'
        local unique_vulns=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | awk -F'|' '{print $2":"$3}' | sort -u | wc -l | tr -d ' ')
        local total_occurrences=${#VULNERABLE_PACKAGES[@]}
        echo '    "total_unique_vulnerabilities": '"$unique_vulns"','
        echo '    "total_occurrences": '"$total_occurrences"
        echo '  }'
        echo "}"
    } > "$output_file"

    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

# Export vulnerabilities to CSV format
# Columns: package, file, severity, ghsa, cve, source, ecosystem
export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"

    # Write CSV header
    echo "package,file,severity,ghsa,cve,source,ecosystem" > "$output_file"

    # Write vulnerability data
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file eco pkg <<< "$vuln"

        # Check both namespaced and name-only (scoped-safe) for metadata
        local meta_key="${eco}:${pkg}"
        local pkg_name_only="${pkg%@*}"
        local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
        local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
        local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
        local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

        # Escape fields that might contain commas
        pkg=$(echo "$pkg" | sed 's/"/""/g')
        file=$(echo "$file" | sed 's/"/""/g')

        echo "\"$pkg\",\"$file\",\"$severity\",\"$ghsa\",\"$cve\",\"$source\",\"$eco\"" >> "$output_file"
    done

    echo -e "${GREEN}✓ CSV report exported to: $output_file${NC}"
}

