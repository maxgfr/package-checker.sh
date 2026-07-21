export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"

    {
        echo "{"
        echo '  "vulnerabilities": ['

        local first=true
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file pkg <<< "$vuln"

            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi

            echo -n '    {'
            echo -n '"package": "'"$pkg"'", '
            echo -n '"file": "'"$file"'"'

            # Add metadata if available (check both exact and package-only)
            local pkg_name_only="${pkg%%@*}"
            local severity="${VULN_METADATA_SEVERITY[$pkg]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
            local ghsa="${VULN_METADATA_GHSA[$pkg]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
            local cve="${VULN_METADATA_CVE[$pkg]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
            local source="${VULN_METADATA_SOURCE[$pkg]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

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
        local unique_vulns=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | cut -d'|' -f2 | sort -u | wc -l | tr -d ' ')
        local total_occurrences=${#VULNERABLE_PACKAGES[@]}
        echo '    "total_unique_vulnerabilities": '"$unique_vulns"','
        echo '    "total_occurrences": '"$total_occurrences"
        echo '  }'
        echo "}"
    } > "$output_file"

    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

# Export vulnerabilities to CSV format
# Columns: package, file, severity, ghsa, cve, source
export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"

    # Write CSV header
    echo "package,file,severity,ghsa,cve,source" > "$output_file"

    # Write vulnerability data
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file pkg <<< "$vuln"

        # Check both exact and package-only for metadata
        local pkg_name_only="${pkg%%@*}"
        local severity="${VULN_METADATA_SEVERITY[$pkg]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
        local ghsa="${VULN_METADATA_GHSA[$pkg]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
        local cve="${VULN_METADATA_CVE[$pkg]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
        local source="${VULN_METADATA_SOURCE[$pkg]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

        # Escape fields that might contain commas
        pkg=$(echo "$pkg" | sed 's/"/""/g')
        file=$(echo "$file" | sed 's/"/""/g')

        echo "\"$pkg\",\"$file\",\"$severity\",\"$ghsa\",\"$cve\",\"$source\"" >> "$output_file"
    done

    echo -e "${GREEN}✓ CSV report exported to: $output_file${NC}"
}

