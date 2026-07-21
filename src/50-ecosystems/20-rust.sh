# Shared TOML "[[package]]" lockfile parser.
#
# Handles Cargo.lock (v3/v4) today; the same block shape (name = "..." /
# version = "..." pairs inside [[package]] tables, keys in any order, plus
# arbitrary other keys like source/checksum/dependencies to ignore) is used
# by poetry.lock, uv.lock and pdm.lock, so later ecosystem tasks can reuse
# this analyzer as-is by adding their own registry row.
analyze_toml_pkg_lock() {
    local lockfile="$1"
    local eco="${2:-cargo}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    local packages
    packages=$(awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "") {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_version = ""
    }
    # Start of a new [[package]] block: flush whatever we collected so far
    /^[[:space:]]*\[\[package\]\][[:space:]]*$/ {
        emit_pkg()
        next
    }
    # Any single-bracket table header (e.g. [metadata], [metadata.files])
    # also ends the current package block.
    /^[[:space:]]*\[[^][]/ {
        emit_pkg()
        next
    }
    /^[[:space:]]*name[[:space:]]*=/ {
        line = $0
        sub(/^[[:space:]]*name[[:space:]]*=[[:space:]]*/, "", line)
        gsub(/^[[:space:]]+/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        gsub(/^"/, "", line)
        gsub(/"$/, "", line)
        pkg_name = line
        next
    }
    /^[[:space:]]*version[[:space:]]*=/ {
        line = $0
        sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*/, "", line)
        gsub(/^[[:space:]]+/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        gsub(/^"/, "", line)
        gsub(/"$/, "", line)
        pkg_version = line
        next
    }
    END { emit_pkg() }
    ' "$lockfile" 2>/dev/null | sort -u)

    # Process extracted packages
    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    # Check if vulnerabilities were found in this file
    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
