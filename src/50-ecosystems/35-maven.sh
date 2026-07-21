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

# Parse a pom.xml. A line-oriented awk state machine walks each <dependency> block
# and captures its <groupId>, <artifactId> and <version> child text (tolerating a
# same-line "<groupId>x</groupId>" form). A dependency is REPORTED only when it has
# a literal, resolvable version: entries whose version is absent or contains "${"
# (an unresolved property such as ${spring.version}) are SKIPPED — this parser does
# NOT resolve properties or parent/dependencyManagement inheritance, a documented
# manifest-grade limitation (the same class of limitation every non-lockfile parser
# in this codebase carries). <dependency> blocks anywhere are accepted (project
# <dependencies> and <dependencyManagement> alike). Nested <exclusions> carry their
# own <groupId>/<artifactId> children, so that region is skipped to avoid clobbering
# the enclosing dependency's coordinates. The opening tag is matched as
# "<dependency" followed by a space or '>' so that "<dependencies>" (the wrapper)
# never triggers a block.
analyze_pom_xml() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    # Return the inner text of <tag>...</tag> on this line, or the sentinel
    # "\001" (never a valid coordinate) when the tag is not present/closed here.
    function inner(line, tag,   open, s, rest, e, val) {
        open = "<" tag ">"
        s = index(line, open)
        if (s == 0) return "\001"
        rest = substr(line, s + length(open))
        e = index(rest, "</" tag ">")
        if (e == 0) return "\001"
        val = substr(rest, 1, e - 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        return val
    }
    BEGIN { in_dep = 0; in_excl = 0 }
    {
        line = $0
        gsub(/\r/, "", line)

        # Open/capture/close are handled within the SAME line pass (not via
        # "next"), so a whole "<dependency>...</dependency>" on one line, or an
        # opening tag sharing a line with its first child, is still captured.
        if (line ~ /<dependency[[:space:]>]/) {
            in_dep = 1; in_excl = 0
            g = ""; a = ""; v = ""; have_v = 0
        }
        if (in_dep) {
            if (line ~ /<exclusions>/) in_excl = 1
            # Skip coordinate capture inside a nested <exclusions> block (its
            # <groupId>/<artifactId> children would otherwise clobber the dep).
            if (!in_excl) {
                val = inner(line, "groupId");    if (val != "\001") g = val
                val = inner(line, "artifactId"); if (val != "\001") a = val
                val = inner(line, "version");    if (val != "\001") { v = val; have_v = 1 }
            }
            if (line ~ /<\/exclusions>/) in_excl = 0
        }
        if (line ~ /<\/dependency>/) {
            if (in_dep && g != "" && a != "" && have_v && v != "" && index(v, "${") == 0) {
                print g ":" a "|" v
            }
            in_dep = 0; in_excl = 0
        }
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
