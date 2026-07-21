analyze_package_lock() {
    local lockfile="$1"

    # Track vulnerabilities found in this file
    local found_in_file=false
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    # Simplified: just scan for node_modules entries with versions
    local packages
    packages=$(awk '
    BEGIN { pkg_name="" }
    {
        # Match node_modules entries: "node_modules/pkg": {
        if (match($0, /"node_modules\/[^"]+"[[:space:]]*:[[:space:]]*\{/)) {
            temp = substr($0, RSTART, RLENGTH)
            sub(/.*"node_modules\//, "", temp)
            sub(/".*/, "", temp)
            pkg_name = temp
            # Get last part after any nested node_modules
            n = split(pkg_name, parts, "node_modules/")
            if (n > 1) pkg_name = parts[n]
        }

        # Match version on same or subsequent line
        if (pkg_name != "" && match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
            temp = substr($0, RSTART, RLENGTH)
            sub(/.*"version"[[:space:]]*:[[:space:]]*"/, "", temp)
            sub(/"$/, "", temp)
            if (temp != "") print pkg_name "|" temp
            pkg_name=""
        }

        # Reset pkg_name if we hit a closing brace (end of package object)
        if (pkg_name != "" && /^[[:space:]]*\},?[[:space:]]*$/) {
            pkg_name=""
        }
    }' "$lockfile" 2>/dev/null | sort -u)

    # Process extracted packages
    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "npm" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    # Check if vulnerabilities were found in this file
    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Function to analyze a yarn.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
# Supports both Yarn Classic (v1) and Yarn Berry (v2+) formats
analyze_yarn_lock() {
    local lockfile="$1"

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
        check_vulnerability "npm" "$pkg_name" "$version" "$lockfile" || true
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
        # Remove leading whitespace
        gsub(/^[[:space:]]+/, "", line)
        # Remove trailing colon
        gsub(/:$/, "", line)
        # Remove surrounding quotes (single or double)
        gsub(/^[\047"]/, "", line)
        gsub(/[\047"]$/, "", line)
        # Remove leading slash (old format)
        gsub(/^\//, "", line)

        # Skip peer dependency entries (contain parentheses)
        if (index(line, "(") > 0) next

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
        check_vulnerability "npm" "$pkg_name" "$version" "$lockfile" || true
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
        check_vulnerability "npm" "$pkg_name" "$version" "$lockfile" || true
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
        check_vulnerability "npm" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    # Check if vulnerabilities were found in this file
    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Export vulnerabilities to JSON format
# Output includes package name, version, severity, GHSA, CVE, and source
