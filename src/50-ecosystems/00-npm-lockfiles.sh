analyze_package_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}
    local packages

    # Read the packages map (v2/v3) or recursive dependencies tree (v1).
    # Structural records keep JSON whitespace and property order irrelevant.
    packages=$(json_structural_lines "$lockfile" | awk '
    function key(line) {
        sub(/^[[:space:]]*"/, "", line)
        sub(/"[[:space:]]*:.*/, "", line)
        gsub(/\\\//, "/", line)
        return line
    }
    function value(line) {
        sub(/^[[:space:]]*"[^"]*"[[:space:]]*:[[:space:]]*"/, "", line)
        sub(/"[[:space:]]*$/, "", line)
        gsub(/\\\//, "/", line)
        return line
    }
    {
        line = $0
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line ~ /[\{\[]$/) {
            field = key(line)
            parent = kind[depth]
            depth++
            kind[depth] = "other"
            names[depth] = versions[depth] = ""
            linked[depth] = 0
            if (depth == 2 && field == "packages") {
                kind[depth] = "packages"
                have_packages = 1
            } else if (field == "dependencies" && (depth == 2 || parent == "legacy")) {
                kind[depth] = "dependencies"
            } else if (parent == "packages" && field ~ /(^|\/)node_modules\//) {
                kind[depth] = "modern"
                sub(/^.*node_modules\//, "", field)
                names[depth] = field
            } else if (parent == "dependencies") {
                kind[depth] = "legacy"
                names[depth] = field
            }
            next
        }
        if (line == "}" || line == "]") {
            if (names[depth] != "" && versions[depth] != "" && !linked[depth]) {
                name = names[depth]; ver = versions[depth]
                if (ver ~ /^npm:/) {
                    sub(/^npm:/, "", ver)
                    if (match(ver, /@[^@]+$/)) {
                        name = substr(ver, 1, RSTART - 1)
                        ver = substr(ver, RSTART + 1)
                    }
                }
                if (kind[depth] == "modern") modern[name "|" ver] = 1
                else if (kind[depth] == "legacy") legacy[name "|" ver] = 1
            }
            depth--
            next
        }
        if (kind[depth] == "modern" || kind[depth] == "legacy") {
            if (line ~ /^"version"[[:space:]]*:[[:space:]]*"/) versions[depth] = value(line)
            else if (line ~ /^"name"[[:space:]]*:[[:space:]]*"/) names[depth] = value(line)
            else if (line ~ /^"link"[[:space:]]*:[[:space:]]*true/) linked[depth] = 1
        }
    }
    END {
        if (have_packages) { for (entry in modern) print entry }
        else { for (entry in legacy) print entry }
    }' | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    if [ "${#VULNERABLE_PACKAGES[@]}" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Function to analyze a yarn.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
# Supports both Yarn Classic (v1) and Yarn Berry (v2+) formats
analyze_yarn_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    local packages
    packages=$(awk '
    # Package name of one yarn descriptor ("name@range", "@scope/name@range").
    # An npm alias "alias@npm:real@^1" installs "real", so return that.
    function spec_name(spec,   at, name, rest) {
        at = index(substr(spec, 2), "@")
        if (at == 0) return ""
        name = substr(spec, 1, at)
        rest = substr(spec, at + 2)
        if (rest ~ /^npm:/) {
            rest = substr(rest, 5)
            at = index(substr(rest, 2), "@")
            if (at > 0) name = substr(rest, 1, at)
        }
        return name
    }
    function flush() {
        if (pkg != "" && ver != "" && ver !~ /^(workspace|file|link|npm|portal|patch|exec):/ && ver != "0.0.0-use.local")
            print pkg "|" ver
        pkg = ver = ""
    }
    { sub(/\r$/, "") }
    # Block header: one or more comma-separated descriptors ending in ":".
    /^[^[:space:]#].*:$/ {
        flush()
        line = $0
        sub(/:$/, "", line)
        gsub(/"/, "", line)
        sub(/,.*/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "__metadata") pkg = spec_name(line)
        next
    }
    # Classic: version "x.y.z"   Berry: version: x.y.z
    /^[[:space:]]+version[[:space:]:]/ && pkg != "" {
        line = $0
        sub(/^[[:space:]]+version[[:space:]:]+/, "", line)
        gsub(/"/, "", line)
        gsub(/[[:space:]].*/, "", line)
        ver = line
        next
    }
    # Berry records the installed package itself: resolution: "real@npm:1.2.3"
    /^[[:space:]]+resolution:[[:space:]]/ && pkg != "" {
        line = $0
        sub(/^[[:space:]]+resolution:[[:space:]]+/, "", line)
        gsub(/"/, "", line)
        at = index(substr(line, 2), "@")
        if (at > 0 && substr(line, at + 2) ~ /^npm:/) pkg = substr(line, 1, at)
        next
    }
    END { flush() }
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

# Function to analyze a pnpm-lock.yaml file
# Optimized: unified awk extraction for both formats (POSIX-compatible)
analyze_pnpm_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    local packages
    packages=$(awk '
    BEGIN { in_packages=0 }
    /^packages:/ { in_packages=1; next }
    /^[a-zA-Z]/ && !/^[[:space:]]/ && in_packages { in_packages=0 }
    in_packages {
        line = $0
        # A package installed from a tarball URL or git ("xlsx@https://...")
        # names no version in its key: pnpm records it in a version: field.
        if (tarball_pkg != "" && line ~ /^    version:[[:space:]]*[^[:space:]]/) {
            version = line
            sub(/^    version:[[:space:]]*/, "", version)
            gsub(/[\047"[:space:]]/, "", version)
            if (version != "") print tarball_pkg "|" version
            tarball_pkg = ""
            next
        }
        # Only package-map keys, never nested dependency metadata.
        if (line !~ /^  [^[:space:]].*:[[:space:]]*$/) next
        tarball_pkg = ""
        # Remove leading whitespace
        gsub(/^[[:space:]]+/, "", line)
        # Remove trailing colon
        gsub(/:[[:space:]]*$/, "", line)
        # Remove surrounding quotes (single or double)
        gsub(/^[\047"]/, "", line)
        gsub(/[\047"]$/, "", line)
        # Remove leading slash (old format)
        gsub(/^\//, "", line)

        # Peer suffixes identify resolutions of this same installed version.
        sub(/\(.*/, "", line)
        # pnpm <=7 uses /name/version, with optional _peer context. The
        # trailing segment must be a version: "@scope/3d-lib@1.0.0" is the
        # modern format with a name that merely starts with a digit.
        if (match(line, /\/[0-9][^\/]*$/)) {
            seg = substr(line, RSTART + 1)
            if (seg ~ /^[0-9]+\.[0-9]+[^@]*(_|$)/) {
                pkg_name = substr(line, 1, RSTART - 1)
                version = seg
                sub(/_.*/, "", version)
                print pkg_name "|" version
                next
            }
        }

        # Remote tarball or git source: the version follows in the block.
        at = index(substr(line, 2), "@")
        if (at > 0 && substr(line, at + 2) ~ /^(https?:|git\+|git:|github:)/) {
            tarball_pkg = substr(line, 1, at)
            next
        }

        # Must contain @ followed by digit (package@version)
        if (match(line, /@[0-9]/)) {
            # Extract package name and version manually
            # Handle scoped packages (@scope/name@version)
            if (substr(line, 1, 1) == "@") {
                # Scoped: find second @
                temp = substr(line, 2)
                idx = index(temp, "@")
                if (idx > 0) {
                    pkg_name = "@" substr(temp, 1, idx-1)
                    version = substr(temp, idx+1)
                    print pkg_name "|" version
                }
            } else {
                # Regular: name@version
                idx = index(line, "@")
                if (idx > 0) {
                    pkg_name = substr(line, 1, idx-1)
                    version = substr(line, idx+1)
                    print pkg_name "|" version
                }
            }
        }
    }
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

# Function to analyze a bun.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
analyze_bun_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    local packages
    packages=$(awk '
    { sub(/\r$/, "") }
    # Top-level keys sit at a two-space indent; only "packages" holds
    # resolved versions ("workspaces" lists the requested specs, e.g. "2").
    /^  "[^"]+"[[:space:]]*:/ {
        section = $0
        sub(/^  "/, "", section)
        sub(/".*/, "", section)
    }
    section != "packages" { next }
    # Remote tarball: ["pkg@https://.../<base>-<version>.tgz", ...]. bun
    # records no version, so read it from the file name; skip it otherwise.
    match($0, /\["[^"]+@https?:[^"]*"/) {
        temp = substr($0, RSTART + 2, RLENGTH - 3)
        idx = index(substr(temp, 2), "@")
        pkg_name = substr(temp, 1, idx)
        file = substr(temp, idx + 2)
        sub(/[?#].*/, "", file)
        sub(/.*\//, "", file)
        sub(/\.(tgz|tar\.gz)$/, "", file)
        base = pkg_name
        sub(/.*\//, "", base)
        if (substr(file, 1, length(base) + 1) == base "-") {
            version = substr(file, length(base) + 2)
            if (version ~ /^[0-9]/) print pkg_name "|" version
        }
        next
    }
    # Match package entries: "pkg": ["pkg@version", ...]
    /\["[^"]+@[0-9]/ {
        line = $0
        # Find the array value ["pkg@version"
        if (match(line, /\["[^"]+@[0-9][^"]*"/)) {
            temp = substr(line, RSTART+2, RLENGTH-3)  # Remove [" and "
            # Split at last @
            idx = 0
            for (i=length(temp); i>0; i--) {
                if (substr(temp, i, 1) == "@") { idx = i; break }
            }
            if (idx > 0) {
                pkg_name = substr(temp, 1, idx-1)
                version = substr(temp, idx+1)
                print pkg_name "|" version
            }
        }
    }
    # Exact dependency pins inside a package entry: "pkg": "1.2.3"
    /"[^"]+": "[0-9]/ {
        line = $0
        # Extract "key": "value" pattern
        if (match(line, /"[^"]+": "[0-9]+\.[0-9]+\.[0-9][^"]*"/)) {
            temp = substr(line, RSTART+1, RLENGTH-2)  # Remove outer quotes
            idx = index(temp, "\": \"")
            if (idx > 0) {
                pkg_name = substr(temp, 1, idx-1)
                version = substr(temp, idx+4)
                gsub(/"$/, "", version)
                print pkg_name "|" version
            }
        }
    }
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

# Function to analyze a deno.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
analyze_deno_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all npm packages in one pass (POSIX-compatible)
    # Simplified: just extract "package@version": or "package@version_peer": patterns
    local packages
    packages=$(awk '
    {
        # Match package keys at start of line: "package@version" or "@scope/pkg@version"
        # Must be followed by ": {" or "_peer": (not inside a string value)
        if (match($0, /^[[:space:]]*"[^"]+@[0-9][^"]*"[[:space:]]*:/)) {
            temp = substr($0, RSTART, RLENGTH)
            # Extract content between first quotes
            gsub(/^[[:space:]]*"/, "", temp)
            gsub(/"[[:space:]]*:.*/, "", temp)

            # Name/version split at the first "@" after the scope marker.
            # Package names may contain "_" (string_decoder): only the
            # version carries the "_peer@x" suffix, so strip it there.
            at_idx = index(substr(temp, 2), "@")
            if (at_idx > 0) {
                pkg_name = substr(temp, 1, at_idx)
                version = substr(temp, at_idx + 2)
                sub(/_.*/, "", version)
                if (pkg_name != "" && version != "") print pkg_name "|" version
            }
        }
    }
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

# Export vulnerabilities to JSON format
# Output includes package name, version, severity, GHSA, CVE, and source
