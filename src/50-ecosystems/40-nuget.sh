# NuGet dependency parser.
#
#   packages.lock.json -> analyze_nuget_lock
#
# (csproj is a tier-2 manifest — no manifest-grade property/MSBuild-condition
# resolution is attempted anywhere else in this codebase either, see pom.xml's
# ${property} skip — so it is NOT registered/parsed at all.)
#
# packages.lock.json is plain JSON (no jq on the scan path) shaped THREE
# levels deep below the root: a single top-level "dependencies" object keyed
# by target framework moniker (e.g. "net8.0"; a multi-targeted project has one
# sibling object per TFM), each holding package-name-keyed objects with a
# "type" ("Direct" | "Transitive" | "Project") and, for Direct/Transitive, a
# "resolved" version. This is one nesting level deeper than composer.lock's
# "packages"/"packages-dev" ARRAY of objects (src/50-ecosystems/30-php.sh), so
# the same JSON brace/bracket DEPTH-TRACKING approach is used here but against
# TWO thresholds instead of composer's one: package names are only captured
# at "framework object contents" depth (deps_depth + 1) and "type"/"resolved"
# fields only at "package object contents" depth (deps_depth + 2). This
# precision matters because a Transitive (or Project) entry commonly carries
# its OWN nested "dependencies" sub-object (name -> requested-range STRING,
# not an object with a "resolved" field) one level deeper still, e.g.:
#   "Serilog.Sinks.Console": {
#     "type": "Transitive", "resolved": "4.1.0",
#     "dependencies": { "Serilog": "3.1.1" }
#   }
# A depth-exact parser skips straight past that nested map (it never reaches
# the field-capture depth), so it can never be mistaken for another package
# or clobber the enclosing entry's own type/resolved - the identical class of
# hardening composer.lock's parser applies to "authors"/"require"/"support".
#
# "type": "Project" entries (an in-solution ProjectReference resolved through
# the lock file, e.g. a referenced class library) carry NO "resolved" field
# at all, so they are skipped by construction: emit_pkg() only prints when
# type is Direct or Transitive AND a resolved version was captured.
#
# NORMALIZATION: package names (the JSON keys themselves) are LOWERCASED
# (NuGet canon - the feed side, data/ghsa-nuget.purl / data/osv-nuget.purl,
# and canon_purl_name() in src/31-parsers-purl.sh, both lowercase nuget names
# already; composer/githubactions share this same canon). Versions are passed
# through verbatim - real "resolved" values are always a bare
# Major.Minor.Patch[.Revision][-prerelease] with no "v" prefix, ordered by
# compare_versions_nuget (src/40-versions/25-nuget.sh).
#
# DEDUPE: a multi-targeted project (TargetFrameworks with more than one TFM)
# repeats every package once per framework block; identical name|version
# pairs collapse via the same `sort -u` every other parser in this codebase
# uses, so a package resolving to the SAME version under both frameworks is
# reported (and checked) exactly once.
analyze_nuget_lock() {
    local lockfile="$1"
    local eco="${2:-nuget}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "" && (pkg_type == "Direct" || pkg_type == "Transitive")) {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_type = ""
        pkg_version = ""
    }
    BEGIN {
        depth = 0
        in_deps = 0
        deps_depth = -1
    }
    {
        line = $0
        gsub(/\r/, "", line)                        # tolerate CRLF checkouts
        start_depth = depth

        # Enter the top-level "dependencies" object at the CURRENT (pre-line)
        # depth. Guarded by !in_deps so a package'\''s own nested "dependencies"
        # sub-object (requested-range strings, no "type"/"resolved" fields -
        # see header) cannot re-trigger this once already inside.
        if (!in_deps && match(line, /"dependencies"[[:space:]]*:[[:space:]]*\{/)) {
            in_deps = 1
            deps_depth = start_depth + 1
            pkg_name = ""
            pkg_type = ""
            pkg_version = ""
        }

        # Package-name keys live one level inside each framework object
        # (deps_depth + 1): "PackageId": { opens a new package entry.
        if (in_deps && start_depth == deps_depth + 1) {
            if (match(line, /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*\{/)) {
                temp = line
                sub(/^[[:space:]]*"/, "", temp)
                sub(/"[[:space:]]*:[[:space:]]*\{.*$/, "", temp)
                if (temp != "") {
                    pkg_name = tolower(temp)
                    pkg_type = ""
                    pkg_version = ""
                }
            }
        }

        # "type"/"resolved" are DIRECT fields of a package object, one level
        # deeper still (deps_depth + 2); a nested per-package "dependencies"
        # map (see header) sits at deps_depth + 3 and is excluded by this
        # check regardless of its own key names.
        if (in_deps && start_depth == deps_depth + 2) {
            if (match(line, /^[[:space:]]*"type"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"type"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_type = temp
            } else if (match(line, /^[[:space:]]*"resolved"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"resolved"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_version = temp
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the pending
        # package the instant its object closes (back to deps_depth + 1),
        # resetting stray state when a framework object closes (deps_depth),
        # and closing "dependencies" itself once depth falls below deps_depth.
        n = length(line)
        in_str = 0
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            if (in_str) {
                if (c == "\\") { i++ }
                else if (c == "\"") { in_str = 0 }
                continue
            }
            if (c == "\"") { in_str = 1; continue }
            if (c == "{" || c == "[") {
                depth++
            } else if (c == "}" || c == "]") {
                depth--
                if (in_deps && depth == deps_depth + 1) {
                    emit_pkg()
                } else if (in_deps && depth == deps_depth) {
                    pkg_name = ""
                    pkg_type = ""
                    pkg_version = ""
                } else if (in_deps && depth < deps_depth) {
                    in_deps = 0
                    deps_depth = -1
                    pkg_name = ""
                    pkg_type = ""
                    pkg_version = ""
                }
            }
        }
    }
    END { emit_pkg() }
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
