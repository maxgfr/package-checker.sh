# Awk helpers shared by every feed parser (purl, SARIF, CycloneDX, Trivy).
# Prepended to each awk program so canonicalization cannot drift between them.
#   escape_sq(s)            quote s for a single-quoted bash eval string
#   canon_purl_name(e, n)   canonical package name for purl type e; MUST match
#                           the feed emission (src/60-feeds.sh) and the lockfile
#                           parsers (src/50-ecosystems/)
#   purl_split(p)           split "pkg:type/name@version?q" into PURL_TYPE,
#                           PURL_NAME, PURL_VERSION (both percent-decoded) and
#                           PURL_QUERY; returns 0 when p is not a versioned purl
#   loose_name(n)           key of a name in the wildcard "*:" namespace
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
function purl_split(p,   main_part, q, te, at) {
    PURL_TYPE = PURL_NAME = PURL_VERSION = PURL_QUERY = ""
    if (substr(p, 1, 4) != "pkg:") return 0
    te = index(p, "/")
    if (te <= 5) return 0
    main_part = p
    q = index(p, "?")
    # The query string may itself contain "@": split it off first.
    if (q > 0) { main_part = substr(p, 1, q - 1); PURL_QUERY = substr(p, q + 1) }
    PURL_TYPE = substr(main_part, 5, te - 5)
    # Name/version split at the LAST "@": scoped names start with "@".
    if (!match(main_part, /@[^@]*$/)) return 0
    at = RSTART
    if (at <= te + 1) return 0
    PURL_NAME = substr(main_part, te + 1, at - te - 1)
    PURL_VERSION = substr(main_part, at + 1)
    if (index(main_part, "\"")) {
        gsub(/"/, "", PURL_NAME)
        gsub(/"/, "", PURL_VERSION)
    }
    PURL_NAME = pct_decode(PURL_NAME)
    PURL_VERSION = pct_decode(PURL_VERSION)
    return PURL_NAME != "" && PURL_VERSION != ""
}
# Decode %XX escapes (%40 "@", %2F "/", %2B "+" in v1.2.3%2Bincompatible).
function pct_decode(s,   out, i, c, hex) {
    if (!index(s, "%")) return s
    out = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        hex = tolower(substr(s, i + 1, 2))
        if (c == "%" && hex ~ /^[0-9a-f][0-9a-f]$/) {
            out = out sprintf("%c", (index("0123456789abcdef", substr(hex, 1, 1)) - 1) * 16 + index("0123456789abcdef", substr(hex, 2, 1)) - 1)
            i += 2
        } else out = out c
    }
    return out
}
# Loose form of a name without ecosystem (wildcard "*:" keys of CSV, JSON and
# report sources): lowercase, runs of - _ . collapsed to "-". Must match the
# probe in check_vulnerability.
function loose_name(n) {
    n = tolower(n)
    gsub(/[-_.]+/, "-", n)
    return n
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
# True when a version string is a range: operators, spaces, wildcards
# (*, 1.x), OR-alternatives (| and ||) or Maven/NuGet intervals ([1.0,2.0)).
function range_like(v) {
    return (v ~ /[[:space:]<>=,^~*|]/ || index(v, "[") || index(v, "]") || v ~ /\.[xX](\.|$)/ || v ~ /^\(/)
}
# Known fixed version of a single range: its exclusive upper bound. An
# inclusive upper bound (<=) is still affected, and an OR-range (or an
# interval list) is ambiguous.
function range_fix(version) {
    if (version !~ /\||\[|\(/ && match(version, /<[0-9][^[:space:],]*/))
        return substr(version, RSTART + 1, RLENGTH - 1)
    return ""
}
# Print the counts first (FEED_PKG_COUNT: packages kept, FEED_RAW_COUNT:
# entries read before pre-filtering), then the eval statements. Appends ("+=")
# merge with tables filled by earlier sources; single quotes keep the data
# literal through eval.
function emit_lookup(   pkg, key) {
    printf "FEED_PKG_COUNT=%d\nFEED_RAW_COUNT=%d\n", key_count, (raw_count != "" ? raw_count : key_count)
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
#
# Pre-filtering: with PREFILTER_TOKENS_FILE set (see build_project_tokens), an
# entry is kept only when the last segment of its name (after the last "/" or
# ":"), lowercased with runs of - _ . collapsed to "-", is one of the project
# tokens. That segment is part of every way a package is written in a
# lockfile (npm scope/name, PEP 503 names, Maven group:artifact, Go module
# paths, Swift repository URLs, NuGet ids...), so no relevant entry is lost
# while a 300k-line feed shrinks to the few entries the project can match.
parse_purl_to_lookup_eval() {
    local file="$1"
    awk -v tokens_file="${PREFILTER_TOKENS_FILE:-}" "$AWK_FEED_LIB"'
    BEGIN {
        raw_count = 0
        filtering = (tokens_file != "")
        if (filtering) while ((getline t < tokens_file) > 0) wanted[t] = 1
    }
    function parse_query_params(query_string, params,   n, i, pairs, eq) {
        delete params
        if (query_string == "") return
        n = split(query_string, pairs, "&")
        for (i = 1; i <= n; i++) {
            eq = index(pairs[i], "=")
            if (eq > 0) params[substr(pairs[i], 1, eq - 1)] = substr(pairs[i], eq + 1)
        }
    }

    {
        # Fast path for generated feeds: one bare purl per line. Anything else
        # (indentation, CRLF, comments, blank lines) goes through a trim.
        line = $0
        last = substr(line, length(line))
        if (substr(line, 1, 4) != "pkg:" || last == "\r" || last == " " || last == "\t") {
            gsub(/^[[:space:]]+|[[:space:]\r]+$/, "", line)
            if (substr(line, 1, 4) != "pkg:") next
        }
        raw_count++
        if (filtering) {
            # Last segment of the name, without decoding the whole purl.
            q = index(line, "?")
            segment = q ? substr(line, 1, q - 1) : line
            sub(/@[^@]*$/, "", segment)
            segment = pct_decode(segment)
            sub(/\/+$/, "", segment)
            sub(/^.*[\/:]/, "", segment)
            segment = tolower(segment)
            gsub(/[-_.]+/, "-", segment)
            if (!(segment in wanted)) next
        }
        if (!purl_split(line)) next
        canon_key = PURL_TYPE ":" canon_purl_name(PURL_TYPE, PURL_NAME)
        version = PURL_VERSION
        parse_query_params(PURL_QUERY, params)

        # Ranges contain operators, spaces, wildcards or OR-alternatives.
        is_range = range_like(version)

        fix = is_range ? range_fix(version) : ""
        if ("fixed" in params) fix = params["fixed"]
        record = params["severity"] ";" params["ghsa"] ";" params["cve"] ";" params["source"] ";" fix ";" params["id"]
        add_entry(canon_key, version, record, is_range)
    }

    END { emit_lookup() }
    ' "$file"
}
