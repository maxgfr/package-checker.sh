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

# Annotate the Go findings with govulncheck's call analysis (--go-reachability):
# VULN_REACHABILITY["dir|golang:module@version"] is "called" when one of the
# module's findings reaches a vulnerable function from the code of the Go
# module in dir, else "not called". govulncheck runs once per go.mod directory whose go.sum or
# go.mod has a finding; a module it says nothing about stays unannotated. In its JSON stream, the first frame
# of a finding's trace is the vulnerable module, and names a function only when
# the code calls it. A missing govulncheck or a failed run only warns: the
# scan result never depends on it.
go_reachability() {
    local vuln file eco dir dirs=""
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file eco _ <<< "$vuln"
        [ "$eco" = golang ] || continue
        finding_dir "$file"
        dir="$FINDING_DIR"
        [ -f "$dir/go.mod" ] || continue
        case $'\n'"$dirs"$'\n' in *$'\n'"$dir"$'\n'*) ;; *) dirs+="${dirs:+$'\n'}$dir" ;; esac
    done
    [ -n "$dirs" ] || return 0
    if ! command -v govulncheck > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  --go-reachability: govulncheck not found (go install golang.org/x/vuln/cmd/govulncheck@latest); Go findings are not annotated${NC}"
        return 0
    fi

    local out err rc annotations module state
    while IFS= read -r dir; do
        out=$(mktemp) || return 0
        register_temp_file "$out"
        err=$(mktemp) || return 0
        register_temp_file "$err"
        echo "🔎 Checking Go reachability with govulncheck in $dir..."
        rc=0
        govulncheck -C "$dir" -format json ./... > "$out" 2> "$err" || rc=$?
        # 3 means "vulnerabilities found" in text mode; JSON mode exits 0.
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
            echo -e "${YELLOW}⚠️  govulncheck failed in $dir (exit $rc): $(head -n 1 "$err"); its Go findings are not annotated${NC}"
            continue
        fi
        annotations=$(json_structural_lines "$out" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
        {
            jp_step($0)
            if (JP_EVENT == "open" && JP_PATH == "/#/finding/trace") frame = 0
            else if (JP_EVENT == "open" && JP_PATH == "/#/finding/trace/#") frame++
            else if (JP_EVENT == "scalar" && JP_PATH == "/#/finding/trace/#" && frame == 1) {
                if (JP_KEY == "module") module = JP_VAL
                else if (JP_KEY == "version") version = JP_VAL
                else if (JP_KEY == "function" && JP_VAL != "") called = 1
            } else if (JP_EVENT == "close" && JP_PATH == "/#/finding") {
                if (module != "" && version != "") {
                    sub(/^v/, "", version)
                    key = module "@" version
                    if (called) state[key] = "called"
                    else if (!(key in state)) state[key] = "not called"
                }
                module = version = ""
                called = 0
            }
        }
        END { for (key in state) print key "|" state[key] }
        ')
        while IFS='|' read -r module state; do
            [ -n "$module" ] || continue
            VULN_REACHABILITY["$dir|golang:$module"]="$state"
        done <<< "$annotations"
    done <<< "$dirs"
}

# Directory of a finding's file, in FINDING_DIR.
finding_dir() {
    FINDING_DIR="${1%/*}"
    [ "$FINDING_DIR" != "$1" ] || FINDING_DIR="."
}

# Reachability of one occurrence (file, eco:name@version) in REACHABILITY,
# empty when govulncheck said nothing about it.
reachability_of() {
    finding_dir "$1"
    REACHABILITY="${VULN_REACHABILITY[$FINDING_DIR|$2]:-}"
}
