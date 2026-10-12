# Awk helpers shared by every feed parser (purl, SARIF, CycloneDX, Trivy).
# Prepended to each awk program so canonicalization cannot drift between them.
#   escape_sq(s)            quote s for a single-quoted bash eval string
#   canon_purl_name(e, n)   canonical package name for purl type e; MUST match
#                           the feed emission (src/60-feeds.sh) and the lockfile
#                           parsers (src/50-ecosystems/)
#   purl_split(p)           split "pkg:type/name@version?q" into PURL_TYPE,
#                           PURL_NAME (percent-decoded), PURL_VERSION and
#                           PURL_QUERY; returns 0 when p is not a versioned purl
#   add_entry / emit_lookup collect rows, then print the bash eval statements
AWK_FEED_LIB='
function escape_sq(s) {
    gsub(/'\''/, "'\''\\'\'''\''", s)
    return s
}
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
        sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", lo)
        sub(/\/+$/, "", lo)
        sub(/\.git$/, "", lo)
        return tolower(lo)
    }
    # npm, golang, cargo, gem, pub, hex and unknown types: name as-is
    return name
}
function purl_split(p,   main_part, q, te, at, i) {
    PURL_TYPE = PURL_NAME = PURL_VERSION = PURL_QUERY = ""
    if (p !~ /^pkg:[^\/]+\//) return 0
    main_part = p
    q = index(p, "?")
    # The query string may itself contain "@": split it off first.
    if (q > 0) { main_part = substr(p, 1, q - 1); PURL_QUERY = substr(p, q + 1) }
    te = index(main_part, "/")
    PURL_TYPE = substr(main_part, 5, te - 5)
    # Name/version split at the LAST "@": scoped names start with "@".
    at = 0
    for (i = length(main_part); i > te; i--) {
        if (substr(main_part, i, 1) == "@") { at = i; break }
    }
    if (at <= te + 1) return 0
    PURL_NAME = substr(main_part, te + 1, at - te - 1)
    PURL_VERSION = substr(main_part, at + 1)
    gsub(/"/, "", PURL_NAME)
    gsub(/"/, "", PURL_VERSION)
    gsub(/%40/, "@", PURL_NAME)
    gsub(/%2[fF]/, "/", PURL_NAME)
    return PURL_NAME != "" && PURL_VERSION != ""
}
# Register one advisory row. key = "eco:name", version = exact version or
# range, record = "severity;ghsa;cve;source;fix;id" (id: the advisory id when
# it is neither a GHSA nor a CVE, e.g. PYSEC-, GO-, RUSTSEC-, MAL-). Ranges are newline-separated
# (they may contain "||"), exact versions "|"-separated. Every distinct record
# is kept, even when two advisories share the same range.
function add_entry(key, version, record, is_range,   meta_key, rk, vk) {
    meta_key = key (is_range ? ":" : "@") version
    rk = meta_key SUBSEP record
    # A record without any metadata adds nothing to the default one.
    if (record !~ /^;*$/ && !(rk in seen_records)) {
        seen_records[rk] = 1
        records[meta_key] = records[meta_key] record "\n"
    }
    vk = key SUBSEP version
    if (vk in seen_versions) return
    seen_versions[vk] = 1
    if (!(key in seen_keys)) { seen_keys[key] = 1; key_count++ }
    if (is_range) {
        pkg_ranges[key] = (key in pkg_ranges) ? pkg_ranges[key] "\n" version : version
    } else {
        pkg_versions[key] = (key in pkg_versions) ? pkg_versions[key] "|" version : version
    }
}
# Known fixed version of a single range: its exclusive upper bound. An
# inclusive upper bound (<=) is still affected, and an OR-range is ambiguous.
function range_fix(version) {
    if (version !~ /\|\|/ && match(version, /<[0-9][^[:space:],]*/))
        return substr(version, RSTART + 1, RLENGTH - 1)
    return ""
}
# Print the package count first (read by load_data_source), then the eval
# statements. Appends ("+=") merge with tables filled by earlier sources;
# single quotes keep the data literal through eval.
function emit_lookup(   pkg, key) {
    printf "FEED_PKG_COUNT=%d\n", key_count
    for (pkg in pkg_versions)
        printf "VULN_EXACT_LOOKUP['\''%s'\'']+='\''|%s'\''\n", escape_sq(pkg), escape_sq(pkg_versions[pkg])
    for (pkg in pkg_ranges)
        printf "VULN_RANGE_LOOKUP['\''%s'\'']+='\''%s\n'\''\n", escape_sq(pkg), escape_sq(pkg_ranges[pkg])
    for (key in records)
        printf "VULN_RECORDS['\''%s'\'']+='\''%s'\''\n", escape_sq(key), escape_sq(records[key])
}
'

# Parse a PURL feed file into lookup-table eval statements.
# Line format: pkg:type/namespace/name@version-or-range?severity=..&ghsa=..
# Example: pkg:npm/lodash@4.17.21
# Example with version range: pkg:npm/express@>=4.0.0 <4.17.0
parse_purl_to_lookup_eval() {
    local file="$1"
    awk "$AWK_FEED_LIB"'
    function parse_query_params(query_string, params,   n, i, pairs, eq) {
        delete params
        if (query_string == "") return
        n = split(query_string, pairs, "&")
        for (i = 1; i <= n; i++) {
            eq = index(pairs[i], "=")
            if (eq > 0) params[substr(pairs[i], 1, eq - 1)] = substr(pairs[i], eq + 1)
        }
    }

    # Skip empty lines and comments
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }

    {
        line = $0
        sub(/\r$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (!purl_split(line)) next
        canon_key = PURL_TYPE ":" canon_purl_name(PURL_TYPE, PURL_NAME)
        version = PURL_VERSION
        parse_query_params(PURL_QUERY, params)

        # Ranges contain operators, spaces, wildcards or OR-alternatives.
        is_range = (version ~ /[[:space:]]|>|<|=|,|\^|~|\*|\|\|/)

        fix = is_range ? range_fix(version) : ""
        if ("fixed" in params) fix = params["fixed"]
        record = params["severity"] ";" params["ghsa"] ";" params["cve"] ";" params["source"] ";" fix ";" params["id"]
        add_entry(canon_key, version, record, is_range)
    }

    END { emit_lookup() }
    ' "$file"
}
