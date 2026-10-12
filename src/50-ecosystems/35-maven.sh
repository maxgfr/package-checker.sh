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
    packages=$(awk '
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
    ' "$lockfile" 2>/dev/null | sort -u)

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
    packages=$(awk '
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    # Inner text of the first <tag>...</tag> in s, or "\001" when absent.
    function inner(s, tag,   open, b, rest, e) {
        open = "<" tag ">"
        b = index(s, open)
        if (b == 0) return "\001"
        rest = substr(s, b + length(open))
        e = index(rest, "</" tag ">")
        if (e == 0) return "\001"
        return trim(substr(rest, 1, e - 1))
    }
    { doc = doc $0 "\n" }
    END {
        gsub(/\r/, "", doc)
        # Drop XML comments (an unterminated one runs to the end of file).
        while ((b = index(doc, "<!--")) > 0) {
            rest = substr(doc, b + 4)
            e = index(rest, "-->")
            doc = substr(doc, 1, b - 1) (e ? substr(rest, e + 3) : "")
        }
        # <properties><name>value</name>...</properties>
        props = inner(doc, "properties")
        if (props != "\001") {
            while (match(props, /<[A-Za-z0-9_.-]+>[^<]*<\//)) {
                m = substr(props, RSTART + 1, RLENGTH - 3)
                gt = index(m, ">")
                prop[substr(m, 1, gt - 1)] = trim(substr(m, gt + 1))
                props = substr(props, RSTART + RLENGTH)
            }
        }
        rest = doc
        while (match(rest, /<dependency[[:space:]>]/)) {
            rest = substr(rest, RSTART + RLENGTH)
            e = index(rest, "</dependency>")
            if (e == 0) break
            block = substr(rest, 1, e - 1)
            rest = substr(rest, e + 13)
            while ((b = index(block, "<exclusions>")) > 0) {
                x = index(substr(block, b), "</exclusions>")
                block = substr(block, 1, b - 1) (x ? substr(block, b + x + 12) : "")
            }
            g = inner(block, "groupId"); a = inner(block, "artifactId"); v = inner(block, "version")
            if (g == "\001" || a == "\001" || g == "" || a == "") continue
            if (v ~ /^\$\{[^}]+\}$/) {
                name = substr(v, 3, length(v) - 3)
                v = (name in prop) ? prop[name] : ""
            }
            # Missing or unresolved versions come from a parent POM or a BOM.
            if (v == "\001" || v == "" || index(v, "${")) { unversioned++; continue }
            # Version ranges are not installed versions.
            if (v ~ /^[\[(]/ || index(v, ",")) continue
            print g ":" a "|" v
        }
        # "-" is never a groupId:artifactId: it carries the unversioned count.
        if (unversioned) print "-|" unversioned
    }
    ' "$lockfile" 2>/dev/null | sort -u)

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
