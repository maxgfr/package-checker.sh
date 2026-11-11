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
    # One streaming pass: records are split at "<", so each one is a tag
    # followed by the text up to the next tag. A stack of open elements gives
    # every value its place: only the direct children of a <dependency> are
    # its coordinates (an <exclusions> block is deeper), and project-level
    # <properties> win over those of a <profile>. Linear in the file size.
    packages=$(awk '
    BEGIN { RS = "<" }
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    function emit(   v, name) {
        v = dep_version
        if (dep_group == "" || dep_artifact == "") return
        if (v ~ /^\$\{[^}]+\}$/) {
            name = substr(v, 3, length(v) - 3)
            v = (name in project_prop) ? project_prop[name] : ((name in other_prop) ? other_prop[name] : "")
        }
        # Missing or unresolved versions come from a parent POM or a BOM.
        if (v == "" || index(v, "${")) { unversioned++; return }
        # Version ranges are not installed versions.
        if (v ~ /^[\[(]/ || index(v, ",")) return
        print dep_group ":" dep_artifact "|" v
    }
    NR == 1 { next }   # text before the first tag
    {
        if (in_comment) {
            if ((e = index($0, "-->")) == 0) next
            in_comment = 0
            next
        }
        if (substr($0, 1, 3) == "!--") {
            if (index(substr($0, 4), "-->") == 0) in_comment = 1
            next
        }
        c = substr($0, 1, 1)
        if (c == "?" || c == "!") next
        gt = index($0, ">")
        if (gt == 0) next
        tag = substr($0, 1, gt - 1)
        text = trim(substr($0, gt + 1))
        gsub(/\r/, "", text)
        if (c == "/") {
            name = trim(substr(tag, 2))
            if (depth > 0 && stack[depth] == name) {
                if (name == "dependency" && depth == dep_depth) { emit(); dep_depth = 0 }
                depth--
            }
            next
        }
        self_closing = (substr(tag, length(tag)) == "/")
        name = tag
        sub(/[[:space:]\/].*$/, "", name)
        if (self_closing) next
        stack[++depth] = name
        parent = stack[depth - 1]
        if (parent == "properties" && depth >= 3) {
            if (depth == 3 && stack[1] == "project") project_prop[name] = text
            else if (!(name in other_prop)) other_prop[name] = text
        }
        if (name == "dependency" && dep_depth == 0) {
            dep_depth = depth; dep_group = dep_artifact = dep_version = ""
        } else if (dep_depth && depth == dep_depth + 1) {
            if (name == "groupId") dep_group = text
            else if (name == "artifactId") dep_artifact = text
            else if (name == "version") dep_version = text
        }
    }
    END {
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
