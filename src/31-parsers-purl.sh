parse_purl_to_lookup_eval() {
    local raw_data="$1"

    # OPTIMIZED: Use awk to parse PURL lines and generate eval commands
    # Key optimizations:
    # 1. Batch all versions/ranges per package before output (reduces eval overhead)
    # 2. Output count first to avoid grep post-processing
    # 3. Use printf for efficient output
    printf '%s\n' "$raw_data" | awk '
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }

    # Compare two semver versions numerically (ignoring pre-release suffixes)
    # Returns: 1 if v1>v2, -1 if v1<v2, 0 if equal
    function compare_vers(v1, v2,   a, b, na, nb, i, max, pa, pb) {
        # Strip pre-release suffix for comparison
        sub(/-.*/, "", v1)
        sub(/-.*/, "", v2)
        na = split(v1, a, ".")
        nb = split(v2, b, ".")
        max = (na > nb) ? na : nb
        for (i = 1; i <= max; i++) {
            pa = (i <= na) ? a[i] + 0 : 0
            pb = (i <= nb) ? b[i] + 0 : 0
            if (pa > pb) return 1
            if (pa < pb) return -1
        }
        return 0
    }

    function parse_query_params(query_string, params) {
        delete params
        if (query_string == "") return

        # Split by & to get individual parameters
        n = split(query_string, pairs, "&")
        for (i = 1; i <= n; i++) {
            if (index(pairs[i], "=") > 0) {
                split(pairs[i], kv, "=")
                params[kv[1]] = kv[2]
            }
        }
    }

    BEGIN {
        pkg_count = 0
    }

    # Skip empty lines and comments
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }

    {
        line = $0
        # Remove leading/trailing whitespace
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        # Parse PURL: pkg:type/namespace/name@version?params or pkg:type/name@version?params
        if (match(line, /^pkg:[^\/]+\/(.+)@(.+)$/)) {
            # Extract the purl type: text between "pkg:" and the first "/"
            type_end = index(line, "/")
            purl_type = substr(line, 5, type_end - 5)
            if (type_end > 0) {
                # Split the query string off FIRST — it may itself contain "@"
                main_part = line
                query_string = ""
                query_pos = index(line, "?")
                if (query_pos > 0) {
                    main_part = substr(line, 1, query_pos - 1)
                    query_string = substr(line, query_pos + 1)
                }

                # Split name/version at the LAST "@" of the pre-query part.
                # Versions/ranges never contain "@"; scoped names start with "@".
                at_pos = 0
                for (scan_i = length(main_part); scan_i > type_end; scan_i--) {
                    if (substr(main_part, scan_i, 1) == "@") { at_pos = scan_i; break }
                }
                if (at_pos > type_end) {
                    # Package name is the FULL path (all components between the
                    # first "/" and the last "@"), e.g. "@babel/traverse".
                    path = substr(main_part, type_end + 1, at_pos - type_end - 1)
                    # Version/range is everything after the last "@"
                    version = substr(main_part, at_pos + 1)

                    # Remove quotes if present
                    gsub(/"/, "", path)
                    gsub(/"/, "", version)

                    # Percent-decode common PURL encodings (%40 -> @, %2F -> /)
                    gsub(/%40/, "@", path)
                    gsub(/%2[fF]/, "/", path)

                    pkg_name = path

                    # Parse query parameters
                    parse_query_params(query_string, params)

                    if (pkg_name != "" && version != "") {
                        # Detect if version is a range (contains space or operators)
                        # But exclude ? from the check as it is now used for params
                        is_range = (version ~ /[[:space:]]|>|<|\^|~|\*|\|\|/)

                        # Create unique key for metadata
                        # For ranges: use pkg_name:range to avoid collision when multiple advisories affect the same package
                        # For exact versions: use pkg_name@version
                        if (is_range) {
                            meta_key = pkg_name ":" version
                        } else {
                            meta_key = pkg_name "@" version
                        }

                        # Store metadata if present
                        if ("severity" in params) {
                            pkg_severity[meta_key] = params["severity"]
                        }
                        if ("ghsa" in params) {
                            pkg_ghsa[meta_key] = params["ghsa"]
                        }
                        if ("cve" in params) {
                            pkg_cve[meta_key] = params["cve"]
                        }
                        if ("source" in params) {
                            pkg_source[meta_key] = params["source"]
                        }

                        # Extract fix version from range upper bound and track patched versions
                        if (is_range) {
                            if (match(version, /<[0-9]/)) {
                                # Extract upper bound: last <X.Y.Z part
                                n_parts = split(version, range_parts, "<")
                                if (n_parts >= 2) {
                                    upper = range_parts[n_parts]
                                    gsub(/^[=[:space:]]+/, "", upper)
                                    gsub(/[[:space:]]+$/, "", upper)
                                    # Store fix version per advisory
                                    pkg_fix[meta_key] = upper
                                    # Track patched versions for GHSA false positive detection
                                    if ("ghsa" in params) {
                                        patched_key = pkg_name ":" params["ghsa"]
                                        if (!(patched_key in pkg_patched) || compare_vers(upper, pkg_patched[patched_key]) > 0) {
                                            pkg_patched[patched_key] = upper
                                        }
                                    }
                                }
                            }
                        }

                        if (is_range) {
                            # Version range
                            if (pkg_name in pkg_ranges) {
                                pkg_ranges[pkg_name] = pkg_ranges[pkg_name] "|" version
                            } else {
                                pkg_ranges[pkg_name] = version
                                pkg_count++
                            }
                        } else {
                            # Exact version
                            if (pkg_name in pkg_versions) {
                                pkg_versions[pkg_name] = pkg_versions[pkg_name] "|" version
                            } else {
                                pkg_versions[pkg_name] = version
                                pkg_count++
                            }
                        }
                    }
                }
            }
        }
    }

    END {
        # OPTIMIZED: Output unique package count FIRST (allows read without grep)
        delete unique_pkgs
        for (pkg in pkg_versions) unique_pkgs[pkg] = 1
        for (pkg in pkg_ranges) unique_pkgs[pkg] = 1
        unique_count = 0
        for (pkg in unique_pkgs) unique_count++
        printf "PURL_PKG_COUNT=%d\n", unique_count

        # Output eval commands for exact versions
        for (pkg in pkg_versions) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_versions[pkg]), escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
        # Output eval commands for version ranges
        for (pkg in pkg_ranges) {
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_ranges[pkg]), escape_sq(pkg), escape_sq(pkg_ranges[pkg])
        }

        # Output eval commands for patched versions (highest upper bound per package:GHSA)
        for (key in pkg_patched) {
            printf "VULN_PATCHED['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_patched[key])
        }

        # Output eval commands for metadata
        for (key in pkg_severity) {
            printf "VULN_METADATA_SEVERITY['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_severity[key])
        }
        for (key in pkg_ghsa) {
            printf "VULN_METADATA_GHSA['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_ghsa[key])
        }
        for (key in pkg_cve) {
            printf "VULN_METADATA_CVE['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_cve[key])
        }
        for (key in pkg_source) {
            printf "VULN_METADATA_SOURCE['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_source[key])
        }
        for (key in pkg_fix) {
            printf "VULN_METADATA_FIX['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_fix[key])
        }
    }
    '
}

# Parse SARIF format to lookup tables
# SARIF format: Static Analysis Results Interchange Format
# Example: Generated by Trivy, Semgrep, etc.
