# Go module dependency parsers.
#
# Two registry rows feed these:
#   go.sum -> analyze_go_sum   (authoritative: the full transitive build list)
#   go.mod -> analyze_go_mod   (fallback ONLY when no go.sum sits beside it)
#
# Canonical package identity is the full, case-sensitive module path (matching
# the golang feed emission, e.g. pkg:golang/golang.org/x/text@...). Versions are
# normalized to bare semver (leading `v` stripped) so exact-version and range
# matching line up with the feeds.

# Parse a go.sum file. Each module contributes up to two lines:
#   <module> <version> h1:<hash>
#   <module> <version>/go.mod h1:<hash>
# The `/go.mod` lines duplicate the module@version pair, so they are skipped.
# go.sum also !-escapes uppercase letters in module paths
# (github.com/!burnt!sushi/toml == github.com/BurntSushi/toml); those are decoded
# back before matching.
analyze_go_sum() {
    local lockfile="$1"
    local eco="${2:-golang}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    # Decode go.sum !-escaping: "!x" -> uppercase X (module paths only).
    function decode_bang(s,   out, i, c, n) {
        out = ""
        n = length(s)
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (c == "!" && i < n) {
                i++
                out = out toupper(substr(s, i, 1))
            } else {
                out = out c
            }
        }
        return out
    }
    {
        if ($0 ~ /^[[:space:]]*$/) next     # blank lines
        mod = $1
        ver = $2
        if (mod == "" || ver == "") next
        if (ver ~ /\/go\.mod$/) next        # skip duplicate /go.mod entries
        sub(/^v/, "", ver)                  # normalize to bare semver
        mod = decode_bang(mod)
        print mod "|" ver
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

# Parse a go.mod file. FALLBACK ONLY: when a go.sum exists next to this go.mod,
# analyze_go_sum already covers the (larger, transitive) build list, so bail out
# silently to avoid double reporting.
#
# Handles both require forms:
#   require mod vX.Y.Z
#   require (
#       mod vX.Y.Z
#       mod vX.Y.Z // indirect
#   )
# `// ...` comments are stripped; module/go/toolchain/replace/exclude directives
# are ignored. go.mod module paths are NOT !-escaped (unlike go.sum).
analyze_go_mod() {
    local lockfile="$1"
    local eco="${2:-golang}"

    # If a go.sum sits beside this go.mod, it is authoritative — do nothing.
    local godir="${lockfile%/*}"
    [ "$godir" = "$lockfile" ] && godir="."
    if [ -f "$godir/go.sum" ]; then
        return 0
    fi

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    BEGIN { in_require = 0 }
    {
        line = $0
        sub(/\/\/.*$/, "", line)            # strip trailing // comment
        gsub(/^[[:space:]]+/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        if (line == "") next

        if (in_require) {
            if (line ~ /^\)/) { in_require = 0; next }
            n = split(line, a, " ")
            if (n >= 2) {
                ver = a[2]; sub(/^v/, "", ver)
                print a[1] "|" ver
            }
            next
        }

        if (line ~ /^require[[:space:]]*\(/) { in_require = 1; next }
        if (line ~ /^require[[:space:]]+/) {
            sub(/^require[[:space:]]+/, "", line)
            n = split(line, a, " ")
            if (n >= 2) {
                ver = a[2]; sub(/^v/, "", ver)
                print a[1] "|" ver
            }
            next
        }
        # module / go / toolchain / replace / exclude directives: ignored
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
