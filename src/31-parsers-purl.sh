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

    # Canonicalize a package name for a given purl type (ecosystem).
    # "name" is the full path (already percent-decoded) between the first "/" and "@".
    function canon_purl_name(eco, name,   lo, cnt, parts) {
        if (eco == "pypi") {
            # PEP 503: lowercase, collapse runs of - _ . to a single -
            lo = tolower(name)
            gsub(/[-_.]+/, "-", lo)
            return lo
        } else if (eco == "maven") {
            # groupId/artifactId -> groupId:artifactId (last two path components)
            if (index(name, ":") > 0) return name
            cnt = split(name, parts, "/")
            if (cnt >= 2) return parts[cnt-1] ":" parts[cnt]
            return name
        } else if (eco == "composer" || eco == "githubactions" || eco == "nuget") {
            return tolower(name)
        } else if (eco == "swift") {
            lo = name
            sub(/^https?:\/\//, "", lo)
            sub(/\.git$/, "", lo)
            return tolower(lo)
        }
        # npm, golang, cargo, gem, pub, hex and unknown types: name as-is
        return name
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

                    # Namespaced lookup key: "eco:name" (eco = purl type, name canonicalized)
                    canon_key = purl_type ":" canon_purl_name(purl_type, pkg_name)

                    # Parse query parameters
                    parse_query_params(query_string, params)

                    if (pkg_name != "" && version != "") {
                        # Detect if version is a range (contains space or operators)
                        # But exclude ? from the check as it is now used for params
                        is_range = (version ~ /[[:space:]]|>|<|\^|~|\*|\|\|/)

                        # Create unique key for metadata, namespaced by ecosystem
                        # For ranges: use eco:name:range to avoid collision when multiple advisories affect the same package
                        # For exact versions: use eco:name@version
                        if (is_range) {
                            meta_key = canon_key ":" version
                        } else {
                            meta_key = canon_key "@" version
                        }

                        # Keep every distinct advisory, even when ranges are identical.
                        # An inclusive upper bound is affected, not a known fixed version.
                        fix = ""
                        if (is_range && version !~ /\|\|/ && match(version, /<[0-9][^[:space:]]*/)) {
                            fix = substr(version, RSTART + 1, RLENGTH - 1)
                        }
                        if ("fixed" in params) fix = params["fixed"]
                        record = params["severity"] ";" params["ghsa"] ";" params["cve"] ";" params["source"] ";" fix
                        record_key = meta_key SUBSEP record
                        if (!(record_key in seen_records)) {
                            seen_records[record_key] = 1
                            records[meta_key] = records[meta_key] record "\n"
                        }

                        if (is_range) {
                            # Version range (keyed by namespaced eco:name)
                            if (canon_key in pkg_ranges) {
                                pkg_ranges[canon_key] = pkg_ranges[canon_key] "\n" version
                            } else {
                                pkg_ranges[canon_key] = version
                                pkg_count++
                            }
                        } else {
                            # Exact version (keyed by namespaced eco:name)
                            if (canon_key in pkg_versions) {
                                pkg_versions[canon_key] = pkg_versions[canon_key] "|" version
                            } else {
                                pkg_versions[canon_key] = version
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
            printf "VULN_EXACT_LOOKUP['\''%s'\'']+='\''|%s'\''\n", escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
        # Output eval commands for version ranges
        for (pkg in pkg_ranges) {
            printf "VULN_RANGE_LOOKUP['\''%s'\'']+='\''%s\n'\''\n", escape_sq(pkg), escape_sq(pkg_ranges[pkg])
        }

        # Single-quoted appends preserve literal data through eval, also on merge.
        for (key in records) {
            printf "VULN_RECORDS['\''%s'\'']+='\''%s'\''\n", escape_sq(key), escape_sq(records[key])
        }
    }
    '
}

# Parse SARIF format to lookup tables
# SARIF format: Static Analysis Results Interchange Format
# Example: Generated by Trivy, Semgrep, etc.
