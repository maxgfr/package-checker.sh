# Python / PyPI dependency parsers.
#
# Registered lockfiles (see 01-registry.sh):
#   requirements.txt -> analyze_requirements_txt   (exact == pins only)
#   poetry.lock / uv.lock / pdm.lock -> analyze_toml_pkg_lock (shared TOML)
#   Pipfile.lock     -> analyze_pipfile_lock        (JSON default+develop)
#
# CRITICAL: package names are compared PEP 503-normalized on BOTH sides. The
# feeds emit normalized names (lowercase; runs of - _ . collapsed to a single
# '-'); every pypi parser normalizes the names it extracts the same way via
# _pypi_normalize_name so scanned names line up with advisory names.

# PEP 503 normalize a package name into the global PEP503_NAME (no subshell):
#   lowercase, then collapse every run of - _ . to a single '-'.
# e.g. Django_REST-framework -> django-rest-framework, Flask..SQL -> flask-sql.
_pypi_normalize_name() {
    local n="${1,,}"
    n="${n//[-_.]/-}"                    # each separator char -> '-'
    while [[ "$n" == *--* ]]; do          # collapse runs of '-' into one
        n="${n//--/-}"
    done
    PEP503_NAME="$n"
}

# Parse a requirements.txt: ONLY fully-pinned exact requirements (name==version,
# also name[extra1,extra2]==version with extras stripped). Everything else is
# skipped on purpose:
#   * inline comments (# ...) and PEP 508 env markers (; python_version < "3.8")
#     are stripped before matching;
#   * -r / -c includes, -e / URL / VCS / path installs, and option lines
#     (--hash=..., --index-url, ...) are skipped (any line starting with '-'
#     or containing a scheme://);
#   * hash-continuation lines and any line ending in a backslash are skipped;
#   * requirements using any operator other than '==' (>=, <=, ~=, !=, ===, >,
#     <) are skipped — a range is not an installed version.
# Extracted names are PEP 503-normalized.
analyze_requirements_txt() {
    local lockfile="$1"
    local eco="${2:-pypi}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    {
        line = $0
        sub(/[[:space:]]*#.*$/, "", line)          # strip inline/full comment
        sub(/;.*$/, "", line)                       # strip PEP 508 env marker
        gsub(/^[[:space:]]+/, "", line)             # trim
        gsub(/[[:space:]]+$/, "", line)
        if (line == "") next
        if (line ~ /^-/) next                       # -r/-c/-e/--hash/--index-url
        if (line ~ /\\$/) next                      # backslash continuation
        if (line ~ /:\/\//) next                    # scheme:// (URL/VCS install)
        gsub(/[[:space:]]*==[[:space:]]*/, "==", line)  # tolerate spaced pins

        # Exact pin only: name[extras]==version, no other operator. The name
        # char class excludes < > ! ~ =, so >=, <=, ~=, != cannot precede the
        # ==; the [^=...] after == rejects === and operator-led versions.
        if (line !~ /^[A-Za-z0-9._-]+(\[[^]]*\])?==[^=<>!~ ]/) next

        eq = index(line, "==")
        name = substr(line, 1, eq - 1)
        ver  = substr(line, eq + 2)
        br = index(name, "[")                       # strip extras
        if (br > 0) name = substr(name, 1, br - 1)
        sub(/[[:space:]].*$/, "", ver)              # drop any trailing tokens
        if (name != "" && ver != "") print name "|" ver
    }
    ' "$lockfile" 2>/dev/null | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        _pypi_normalize_name "$pkg_name"
        check_vulnerability "$eco" "$PEP503_NAME" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Parse a Pipfile.lock (pipenv, JSON). Packages live under the top-level
# "default" and "develop" objects as name -> { ... "version": "==x.y.z" ... }.
# Entries without a "==" version (e.g. VCS/editable refs pinned by git ref) are
# skipped. Names are PEP 503-normalized. jq-free (POSIX awk state machine).
analyze_pipfile_lock() {
    local lockfile="$1"
    local eco="${2:-pypi}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    BEGIN { section = 0; pkg = "" }
    # Enter a dependency section.
    /^[[:space:]]*"(default|develop)"[[:space:]]*:[[:space:]]*\{/ {
        section = 1; pkg = ""; next
    }
    # Any other top-level (4-space) key ("_meta", ...) leaves the section.
    /^    "[^"]+"[[:space:]]*:/ { section = 0; pkg = ""; next }
    section == 0 { next }
    # A package-name key (deeper-indented "name": {) opens a package object.
    /^[[:space:]]+"[^"]+"[[:space:]]*:[[:space:]]*\{/ {
        s = $0
        sub(/^[[:space:]]+"/, "", s)
        sub(/".*/, "", s)
        pkg = s
        next
    }
    # The pinned version line inside the current package object.
    pkg != "" && /"version"[[:space:]]*:[[:space:]]*"==/ {
        s = $0
        sub(/.*"version"[[:space:]]*:[[:space:]]*"==/, "", s)
        sub(/".*/, "", s)
        if (s != "") print pkg "|" s
        next
    }
    ' "$lockfile" 2>/dev/null | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        _pypi_normalize_name "$pkg_name"
        check_vulnerability "$eco" "$PEP503_NAME" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
