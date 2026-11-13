# Maven (JVM) dependency parsers.
#
#   gradle.lockfile -> analyze_gradle_lockfile   (Gradle's resolved dependency lock)
#   pom.xml         -> analyze_pom_xml           (Maven manifest, direct deps)
#
# Canonical package identity is "groupId:artifactId" (the ONLY ecosystem whose
# canonical names contain a ':'). This matches the feed emission: the purl parser
# canonicalizes pkg:maven/groupId/artifactId to the key "maven:groupId:artifactId"
# (canon_purl_name joins the last two path components with ':', see
# src/31-parsers-purl.sh), and check_vulnerability probes "maven:<name>", so a
# parser that emits "groupId:artifactId" lines up exactly. Versions are passed
# through verbatim and ordered by compare_versions_maven (ComparableVersion).

# Parse a gradle.lockfile. Format (one dependency per line):
#   group:artifact:version=conf1,conf2,...
# plus a header comment block (lines starting with '#') and a trailing sentinel
#   empty=conf,...
# listing configurations that resolved to nothing. Comments and the "empty="
# sentinel carry no package, so they are skipped. The key (left of '=') splits on
# ':' into exactly group / artifact / version (Maven coordinates never contain a
# ':' in any single component), so a line that does not split into three is not a
# coordinate and is ignored.
analyze_gradle_lockfile() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(set -o pipefail; awk '
    {
        line = $0
        gsub(/\r/, "", line)                       # tolerate CRLF checkouts
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line == "") next
        if (line ~ /^#/) next                      # header comment lines
        eq = index(line, "=")
        if (eq == 0) next
        key = substr(line, 1, eq - 1)
        if (key == "empty") next                   # "empty=" sentinel
        n = split(key, a, ":")
        if (n != 3) next                           # not a group:artifact:version
        if (a[1] == "" || a[2] == "" || a[3] == "") next
        print a[1] ":" a[2] "|" a[3]
    }
    ' "$lockfile" 2>/dev/null | sort -u) || { report_parser_failure "$lockfile"; return 0; }

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Parse a pom.xml. The whole file is read into one string so tags split over
# several lines (<version>\n  1.2.3\n</version>) parse like single-line ones,
# and XML comments are removed first (a commented-out <dependency> is not a
# dependency). Each <dependency> block yields its <groupId>, <artifactId> and
# <version>; nested <exclusions> are cut out so their coordinates cannot
# clobber the dependency's. A version "${name}" is resolved from the same
# file's <properties>; anything else that is not a literal version is SKIPPED:
# unresolved properties (parent POMs, ${project.version}), dependencyManagement
# inheritance (no version at all) and version ranges ("[1.0,2.0)"). This is a
# manifest-grade parser — the same class of limitation every non-lockfile
# parser in this codebase carries; the missing and unresolved versions are
# counted and reported once, pointing to --sbom. <dependency> blocks anywhere are accepted
# (project <dependencies> and <dependencyManagement> alike); the opening tag is
# matched as "<dependency" followed by a space or '>' so that the
# "<dependencies>" wrapper never opens a block.
analyze_pom_xml() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    # One streaming pass: records are split at "<", so each one is a tag
    # followed by the text up to the next tag. A stack of open elements gives
    # every value its place: only the direct children of a <dependency> are
    # its coordinates (an <exclusions> block is deeper), and project-level
    # <properties> win over those of a <profile>. Versions are resolved at the
    # end: <properties> may follow <dependencies>. Linear in the file size.
    packages=$(set -o pipefail; awk '
    BEGIN { RS = "<" }
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    # Text of the element that is currently open ("" target: ignored). Text
    # after a comment inside an element (<version><!-- x -->1.0</version>)
    # is appended to it.
    function set_text(value, append) {
        if (target == "") return
        if (append) value = target_value[target] value
        target_value[target] = value
    }
    NR == 1 { next }   # text before the first tag
    {
        record = $0
        gsub(/\r/, "", record)
        if (in_comment || substr(record, 1, 3) == "!--") {
            e = index(record, "-->")
            if (substr(record, 1, 3) == "!--") {
                e = index(substr(record, 4), "-->")
                if (e) e += 3
            }
            if (e == 0) { in_comment = 1; next }
            in_comment = 0
            set_text(trim(substr(record, e + 3)), 1)
            next
        }
        c = substr(record, 1, 1)
        if (c == "?" || c == "!") next
        gt = index(record, ">")
        if (gt == 0) next
        tag = substr(record, 1, gt - 1)
        text = trim(substr(record, gt + 1))
        if (c == "/") {
            name = trim(substr(tag, 2))
            if (depth > 0 && stack[depth] == name) {
                if (name == "dependency" && depth == dep_depth) dep_depth = 0
                depth--
            }
            target = ""
            next
        }
        self_closing = (substr(tag, length(tag)) == "/")
        name = tag
        sub(/[[:space:]\/].*$/, "", name)
        if (self_closing) next
        stack[++depth] = name
        parent = stack[depth - 1]
        target = ""
        if (parent == "properties" && depth >= 3) {
            if (depth == 3 && stack[1] == "project") target = "pp:" name
            else if (!(("op:" name) in target_value)) target = "op:" name
        }
        if (name == "dependency" && dep_depth == 0) {
            dep_depth = depth
            n_deps++
        } else if (dep_depth && depth == dep_depth + 1 &&
                   (name == "groupId" || name == "artifactId" || name == "version")) {
            target = "d" n_deps ":" name
        }
        set_text(text, 0)
    }
    END {
        for (i = 1; i <= n_deps; i++) {
            g = trim(target_value["d" i ":groupId"])
            a = trim(target_value["d" i ":artifactId"])
            v = trim(target_value["d" i ":version"])
            if (g == "" || a == "") continue
            if (v ~ /^\$\{[^}]+\}$/) {
                name = substr(v, 3, length(v) - 3)
                v = ("pp:" name) in target_value ? target_value["pp:" name] : \
                    (("op:" name) in target_value ? target_value["op:" name] : "")
                v = trim(v)
            }
            # Missing or unresolved versions come from a parent POM or a BOM.
            if (v == "" || index(v, "${")) { unversioned++; continue }
            # Version ranges are not installed versions.
            if (v ~ /^[\[(]/ || index(v, ",")) continue
            print g ":" a "|" v
        }
        # "-" is never a groupId:artifactId: it carries the unversioned count.
        if (unversioned) print "-|" unversioned
    }
    ' "$lockfile" 2>/dev/null | sort -u) || { report_parser_failure "$lockfile"; return 0; }

    local unversioned=0
    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        if [ "$pkg_name" = "-" ]; then unversioned="$version"; continue; fi
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    if [ "$unversioned" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  $unversioned dependencies in $lockfile have no version here (managed by a parent POM or BOM): scan a CycloneDX SBOM with --sbom (cyclonedx-maven-plugin) or a gradle.lockfile to check them${NC}"
    fi

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
