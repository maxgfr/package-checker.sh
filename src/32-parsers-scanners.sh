# JSON-shaped source importers: SARIF, CycloneDX SBOM, Trivy JSON and the
# native JSON source format.
#
# Every importer reads json_structural_lines output (one JSON token group per
# record), so pretty-printed and minified reports parse identically, and walks
# it with the path tracker below. Each finding becomes an exact-version entry
# plus an advisory record, through the same add_entry/emit_lookup helpers as
# the purl parser (AWK_FEED_LIB in src/31-parsers-purl.sh).

# Awk JSON path tracker over json_structural_lines records. jp_step(line)
# classifies the record (JP_EVENT = open | close | scalar), keeps a stack of
# container names ("#" for an array element) and exposes JP_PATH, e.g.
# "/#/runs/#/results/#" inside a SARIF result. For a scalar, JP_KEY/JP_VAL hold
# the key and the unquoted value (escapes such as \n stay literal). On close,
# JP_PATH is the path of the container that just closed.
AWK_JSON_PATH='
function jp_step(line,   k, rest) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    JP_KEY = JP_VAL = ""
    if (line == "}" || line == "]") {
        JP_EVENT = "close"
        JP_PATH = jp_path()
        if (jp_depth > 0) jp_depth--
        return
    }
    k = "#"
    rest = line
    if (match(line, /^"([^"\\]|\\.)*"[[:space:]]*:[[:space:]]*/)) {
        k = substr(line, 1, RLENGTH)
        sub(/"[[:space:]]*:[[:space:]]*$/, "", k)
        k = substr(k, 2)
        rest = substr(line, RLENGTH + 1)
    }
    if (rest == "{" || rest == "[") {
        JP_EVENT = "open"
        jp_stack[++jp_depth] = k
        JP_PATH = jp_path()
        return
    }
    JP_EVENT = "scalar"
    JP_PATH = jp_path()
    JP_KEY = k
    if (rest ~ /^".*"$/) rest = substr(rest, 2, length(rest) - 2)
    JP_VAL = rest
}
function jp_path(   i, p) {
    p = ""
    for (i = 1; i <= jp_depth; i++) p = p "/" jp_stack[i]
    return p
}
# Advisory identifier -> ghsa/cve fields of a record.
function id_fields(id) {
    ID_GHSA = ID_CVE = ID_OTHER = ""
    if (id ~ /^GHSA-/) ID_GHSA = id
    else if (id ~ /^CVE-/) ID_CVE = id
    else ID_OTHER = id
}
# Register a finding: namespaced key from a purl when available, else the
# wildcard namespace "*:" (the report carries no ecosystem).
function add_finding(purl, name, version, severity, id, source,   key) {
    key = ""
    if (purl != "" && purl_split(purl)) {
        key = PURL_TYPE ":" canon_purl_name(PURL_TYPE, PURL_NAME)
        if (version == "") version = PURL_VERSION
    } else if (name != "") {
        key = "*:" name
    }
    if (key == "" || version == "") return
    id_fields(id)
    add_entry(key, version, tolower(severity) ";" ID_GHSA ";" ID_CVE ";" source ";;" ID_OTHER, 0)
}
'

# Parse a SARIF report (Trivy, Grype, ...). Each runs[].results[] entry is one
# finding. The package comes from the Trivy-style message
# ("Package: next\nInstalled Version: 16.0.3\n...") or, failing that, from a
# location message "path: name@version" (split at the LAST "@" so scoped names
# survive). ruleId carries the advisory identifier.
parse_sarif_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    function reset() { rule = level = pkg = ver = loc_pkg = loc_ver = sev = "" }
    function field(text, label,   s) {
        s = index(text, label)
        if (s == 0) return ""
        text = substr(text, s + length(label))
        sub(/\\n.*/, "", text)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", text)
        return text
    }
    BEGIN { reset() }
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/results\/#$/ && JP_KEY == "ruleId") rule = JP_VAL
            else if (JP_PATH ~ /\/results\/#$/ && JP_KEY == "level") level = JP_VAL
            else if (JP_PATH ~ /\/results\/#\/message$/ && JP_KEY == "text") {
                pkg = field(JP_VAL, "Package: ")
                ver = field(JP_VAL, "Installed Version: ")
                sev = field(JP_VAL, "Severity: ")
            } else if (JP_PATH ~ /\/locations\/#\/(physicalLocation\/)?message$/ && JP_KEY == "text" && loc_pkg == "") {
                t = JP_VAL
                sub(/^.*:[[:space:]]+/, "", t)
                at = 0
                for (i = length(t); i > 1; i--) if (substr(t, i, 1) == "@") { at = i; break }
                if (at > 1) { loc_pkg = substr(t, 1, at - 1); loc_ver = substr(t, at + 1) }
            }
        } else if (JP_EVENT == "close" && JP_PATH ~ /\/results\/#$/) {
            if (pkg == "" || ver == "") { pkg = loc_pkg; ver = loc_ver }
            if (sev == "") sev = (level == "error" ? "high" : (level == "warning" ? "medium" : ""))
            add_finding("", pkg, ver, sev, rule, "sarif")
            reset()
        }
    }
    END { emit_lookup() }
    '
}

# Parse a CycloneDX SBOM. Each vulnerabilities[] entry lists affects[].ref,
# which is either a purl or a bom-ref resolved through components[] (at any
# nesting depth). Explicit affects[].versions[] with status "affected" are
# added too. References are resolved at the end, since components may follow
# the vulnerabilities.
parse_sbom_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/components\/#$/) {
                if (JP_KEY == "bom-ref") comp_ref = JP_VAL
                else if (JP_KEY == "purl") comp_purl = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#$/ && JP_KEY == "id") {
                vid = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/ratings\/#$/ && JP_KEY == "severity" && vsev == "") {
                vsev = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#$/ && JP_KEY == "ref") {
                refs[++nrefs] = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#\/versions\/#$/) {
                if (JP_KEY == "version") aver = JP_VAL
                else if (JP_KEY == "status") astatus = JP_VAL
            }
        } else if (JP_EVENT == "close") {
            if (JP_PATH ~ /\/components\/#$/) {
                if (comp_ref != "" && comp_purl != "") purl_of[comp_ref] = comp_purl
                comp_ref = comp_purl = ""
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#\/versions\/#$/) {
                if (aver != "" && (astatus == "" || astatus == "affected")) extra[nrefs] = extra[nrefs] " " aver
                aver = astatus = ""
            } else if (JP_PATH ~ /\/vulnerabilities\/#$/) {
                for (r = 1; r <= nrefs; r++) {
                    n = ++nfind
                    find_ref[n] = refs[r]; find_id[n] = vid; find_sev[n] = vsev
                    find_extra[n] = extra[r]
                }
                delete refs; delete extra
                nrefs = 0; vid = vsev = ""
            }
        }
    }
    END {
        for (n = 1; n <= nfind; n++) {
            p = find_ref[n]
            if (p !~ /^pkg:/ && (p in purl_of)) p = purl_of[p]
            if (p !~ /^pkg:/) continue
            add_finding(p, "", "", find_sev[n], find_id[n], "cyclonedx")
            cnt = split(find_extra[n], vers, " ")
            for (v = 1; v <= cnt; v++) if (vers[v] != "") add_finding(p, "", vers[v], find_sev[n], find_id[n], "cyclonedx")
        }
        emit_lookup()
    }
    '
}

# Print "eco|name|version" for every component of a CycloneDX SBOM (--sbom),
# at any nesting depth, from its purl. metadata.component is the project
# itself and metadata.tools lists the generators: neither is a dependency.
# Go purls carry a "v" prefix that go.sum parsing strips too.
cyclonedx_components() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT != "scalar" || JP_KEY != "purl" || JP_PATH !~ /\/components\/#$/ || JP_PATH ~ /^\/#\/metadata\//) next
        gsub(/\\\//, "/", JP_VAL)
        if (!purl_split(JP_VAL)) next
        if (PURL_TYPE == "golang") sub(/^v/, "", PURL_VERSION)
        print PURL_TYPE "|" canon_purl_name(PURL_TYPE, PURL_NAME) "|" PURL_VERSION
    }
    ' | sort -u
}

# Check the components of a CycloneDX SBOM given with --sbom, like a lockfile.
# A Maven build lists its transitive dependencies only there (pom.xml does not).
analyze_cyclonedx_inventory() {
    local lockfile="$1"
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}
    local packages eco pkg_name version
    packages=$(cyclonedx_components "$lockfile")
    while IFS='|' read -r eco pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Parse a Trivy JSON report (trivy fs/image --format json). Each
# Results[].Vulnerabilities[] entry is one finding; PkgIdentifier.PURL gives the
# ecosystem when present, otherwise the wildcard namespace is used.
parse_trivy_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#$/) {
                if (JP_KEY == "PkgName") pkg = JP_VAL
                else if (JP_KEY == "InstalledVersion") ver = JP_VAL
                else if (JP_KEY == "VulnerabilityID") vid = JP_VAL
                else if (JP_KEY == "Severity") sev = JP_VAL
            } else if (JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#\/PkgIdentifier$/ && JP_KEY == "PURL") {
                purl = JP_VAL
            }
        } else if (JP_EVENT == "close" && JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#$/) {
            add_finding(purl, pkg, ver, sev, vid, "trivy")
            pkg = ver = vid = sev = purl = ""
        }
    }
    END { emit_lookup() }
    '
}

# Parse the JSON source format: { "<package>": { "versions": [...],
# "versions_range": [...], "severity", "ghsa", "cve", "source" } }. JSON
# sources carry no ecosystem, so entries land in the wildcard namespace "*:".
# Package objects sit at depth 2 (their names may contain "/", so depth is
# used rather than JP_PATH patterns).
parse_json_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "open" && jp_depth == 2) {
            pkg = jp_stack[2]; nv = 0; sev = ghsa = cve = src = ""
        } else if (JP_EVENT == "scalar" && jp_depth == 2 && pkg != "") {
            if (JP_KEY == "severity") sev = JP_VAL
            else if (JP_KEY == "ghsa") ghsa = JP_VAL
            else if (JP_KEY == "cve") cve = JP_VAL
            else if (JP_KEY == "source") src = JP_VAL
        } else if (JP_EVENT == "scalar" && jp_depth == 3 && pkg != "" && JP_VAL != "" &&
                   (jp_stack[3] == "versions" || jp_stack[3] == "versions_range")) {
            vals[++nv] = JP_VAL
            ranged[nv] = (jp_stack[3] == "versions_range")
        } else if (JP_EVENT == "close" && jp_depth == 1 && pkg != "") {
            # jp_depth is already popped: the package object just closed.
            for (i = 1; i <= nv; i++) {
                record = tolower(sev) ";" ghsa ";" cve ";" src ";" (ranged[i] ? range_fix(vals[i]) : "") ";"
                add_entry("*:" pkg, vals[i], record, ranged[i])
            }
            pkg = ""
        }
    }
    END { emit_lookup() }
    '
}
