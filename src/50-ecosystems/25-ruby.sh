# Ruby (Bundler) dependency parser.
#
#   Gemfile.lock -> analyze_gemfile_lock
#
# Gemfile.lock shape (indentation is significant and exact):
#   GIT / PATH / GEM     column-0 section headers, one or more of each
#     remote: ...          2-space
#     specs:                2-space
#       name (version)        4-space  <- the installed package + version
#         dep (~> x.y)           6-space <- a dependency CONSTRAINT, not a
#                                            resolved package: skip it
#   PLATFORMS / DEPENDENCIES / CHECKSUMS / BUNDLED WITH / RUBY VERSION  column-0
#
# ONLY the "GEM" section's "specs:" packages are resolved gems installed from
# a rubygems source; GIT and PATH sections have the identical "specs:" shape
# but pin a local/VCS gem instead (no rubygems version to check against
# advisories), so they must be excluded the same way npm parsers skip `link:`
# workspace deps. The state machine below re-evaluates on every column-0
# (unindented) line: `in_gem` is set only while inside a literal "GEM"
# header, and cleared by ANY other column-0 line (GIT, PATH, PLATFORMS,
# DEPENDENCIES, CHECKSUMS, BUNDLED WITH, RUBY VERSION, or a second "GIT"/
# "PATH" block) — so it also correctly re-opens across multiple GEM blocks
# (multiple gem sources) without hardcoding every non-GEM header name.
#
# The exactly-4-space check (`^    [^ ]`) is what tells a resolved spec line
# apart from a 6-space dependency-constraint line: a 6-space line still has
# 4 leading spaces, but its 5th character is ALSO a space, so it fails to
# match.
#
# Platform-suffixed versions (native gems, e.g. `nokogiri (1.16.5-arm64-darwin)`)
# are stripped to the bare version: a version starting with a digit followed
# by `-<tail>` where the tail contains a known gem-platform token (darwin,
# linux, x86_64, aarch64, arm64, universal, java, mingw, mswin, freebsd) has
# the `-<tail>` dropped. A real prerelease dash (`1.0.0-rc1`) does not match
# any platform token, so it is left alone (RubyGems itself treats `-` as a
# prerelease separator; see compare_versions_gem).
analyze_gemfile_lock() {
    local lockfile="$1"
    local eco="${2:-gem}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    BEGIN { in_gem = 0 }
    # Column-0 (unindented) line: a new top-level section. Re-evaluate
    # in_gem; every non-"GEM" header (and blank-adjacent noise) closes the
    # capture window until the next literal "GEM" header.
    /^[A-Za-z]/ {
        if ($0 ~ /^GEM[[:space:]]*$/) { in_gem = 1 } else { in_gem = 0 }
        next
    }
    !in_gem { next }
    # Exactly-4-space "name (version)" spec line (6-space dependency
    # constraints fail this match on purpose - see header comment).
    /^    [^ ]/ {
        line = $0
        sub(/^    /, "", line)
        paren = index(line, " (")
        if (paren == 0) next
        name = substr(line, 1, paren - 1)
        rest = substr(line, paren + 2)
        closepos = index(rest, ")")
        if (closepos == 0) next
        ver = substr(rest, 1, closepos - 1)
        if (name == "" || ver == "") next

        # Platform-suffix strip (see header comment).
        if (ver ~ /^[0-9][0-9A-Za-z.]*-/) {
            dash = index(ver, "-")
            base_ver = substr(ver, 1, dash - 1)
            suffix = substr(ver, dash + 1)
            if (suffix ~ /(x86_64|aarch64|arm64|universal|java|mingw|mswin|darwin|linux|freebsd)/) {
                ver = base_ver
            }
        }
        print name "|" ver
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
