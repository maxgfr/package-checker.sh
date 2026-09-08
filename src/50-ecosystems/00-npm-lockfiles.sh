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
    BEGIN { pkg="" }
    /^[^[:space:]].*:$/ && !/^[[:space:]]/ {
        line = $0
        gsub(/:$/, "", line)
        gsub(/"/, "", line)
        # Handle scoped packages: @scope/name@version
        # Extract package name (before first @version part)
        if (substr(line, 1, 1) == "@") {
            # Scoped package: @scope/name@version
            # Find second @ which separates name from version
            temp = substr(line, 2)  # Remove leading @
            idx = index(temp, "@")
            if (idx > 0) {
                pkg = "@" substr(temp, 1, idx-1)
            }
        } else {
            # Regular package: name@version or name@npm:version (Yarn Berry)
            idx = index(line, "@")
            if (idx > 0) {
                pkg = substr(line, 1, idx-1)
            }
        }
    }
    # Match both Yarn Classic (version "x.y.z") and Yarn Berry (version: x.y.z) formats
    /^[[:space:]]+version[[:space:]:]/ && pkg != "" {
        line = $0
        # Extract version value - handle both formats
        sub(/.*version[[:space:]:]+/, "", line)
        gsub(/"/, "", line)
        gsub(/[[:space:]].*/, "", line)
        # Skip non-semver versions (workspace, file, link references)
        if (line ~ /^(workspace|file|link|npm):/ || line == "0.0.0-use.local" || line == "") {
            pkg=""
            next
        }
        print pkg "|" line
        pkg=""
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
        # Only package-map keys, never nested dependency metadata.
        if (line !~ /^  [^[:space:]].*:[[:space:]]*$/) next
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
        # pnpm <=7 uses /name/version, with optional _peer context.
        if (match(line, /\/[0-9][^\/]*$/)) {
            pkg_name = substr(line, 1, RSTART - 1)
            version = substr(line, RSTART + 1)
            sub(/_.*/, "", version)
            print pkg_name "|" version
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
    # Match workspace deps: "pkg": "version"
    /"[^"]+": "[0-9]/ {
        line = $0
        # Extract "key": "value" pattern
        if (match(line, /"[^"]+": "[0-9][^"]*"/)) {
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

            # Remove anything after underscore (peer deps)
            idx = index(temp, "_")
            if (idx > 0) temp = substr(temp, 1, idx-1)

            # Extract package name and version
            # Handle scoped packages
            if (substr(temp, 1, 1) == "@") {
                # Find second @
                rest = substr(temp, 2)
                at_idx = index(rest, "@")
                if (at_idx > 0) {
                    pkg_name = "@" substr(rest, 1, at_idx-1)
                    version = substr(rest, at_idx+1)
                    print pkg_name "|" version
                }
            } else {
                at_idx = index(temp, "@")
                if (at_idx > 0) {
                    pkg_name = substr(temp, 1, at_idx-1)
                    version = substr(temp, at_idx+1)
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

# Export vulnerabilities to JSON format
# Output includes package name, version, severity, GHSA, CVE, and source
