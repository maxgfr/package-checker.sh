# Shared TOML "[[package]]" lockfile parser.
#
# Handles Cargo.lock (v3/v4) today; the same block shape (name = "..." /
# version = "..." pairs inside [[package]] tables, keys in any order, plus
# arbitrary other keys like source/checksum/dependencies to ignore) is reused
# by poetry.lock, uv.lock and pdm.lock (registered by the Python task).
#
# HARDENING (subtable gap): name/version are only captured while INSIDE a
# top-level [[package]] table — i.e. between a `[[package]]` header and the NEXT
# `[`-prefixed header of ANY kind. Entering a subtable such as
# [package.dependencies] / [package.extras] / [package.source] (or [metadata],
# etc.) closes the capture window, so a dependency literally keyed `name` or
# `version` inside a subtable can never leak a bogus pair.
#
# NORMALIZATION: when eco = pypi, package names are PEP 503-normalized
# (lowercase; runs of - _ . collapsed to a single -) so they line up with the
# normalized feed names. cargo names are left untouched.
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
    # Start of a new [[package]] block: flush, then open the capture window.
    /^[[:space:]]*\[\[package\]\][[:space:]]*$/ {
        emit_pkg()
        in_pkg = 1
        next
    }
    # ANY other bracketed header (single-bracket subtable like
    # [package.dependencies], [metadata], or a different [[...]] array) flushes
    # and CLOSES the capture window until the next [[package]].
    /^[[:space:]]*\[/ {
        emit_pkg()
        in_pkg = 0
        next
    }
    in_pkg && /^[[:space:]]*name[[:space:]]*=/ {
        line = $0
        sub(/^[[:space:]]*name[[:space:]]*=[[:space:]]*/, "", line)
        gsub(/^[[:space:]]+/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        gsub(/^"/, "", line)
        gsub(/"$/, "", line)
        pkg_name = line
        next
    }
    in_pkg && /^[[:space:]]*version[[:space:]]*=/ {
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
        # PEP 503 name normalization for pypi locks (cargo names untouched).
        if [ "$eco" = "pypi" ]; then
            _pypi_normalize_name "$pkg_name"
            pkg_name="$PEP503_NAME"
        fi
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    # Check if vulnerabilities were found in this file
    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
