analyze_package_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}
    local packages

    # Read the packages map (v2/v3) or recursive dependencies tree (v1).
    # Structural records keep JSON whitespace and property order irrelevant.
    packages=$(set -o pipefail; json_structural_lines "$lockfile" | awk '
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
    }' | sort -u) || { report_parser_failure "$lockfile"; return 0; }

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
# Supports both Yarn Classic (v1) and Yarn Berry (v2+) formats.
# An optional third argument is the file to read, findings being reported
# against the first (bun.lockb printed as a yarn v1 lockfile).
analyze_yarn_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"
    local lock_text="${3:-$1}"

    # Track vulnerabilities found in this file
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    # Use awk to extract all packages in one pass (POSIX-compatible)
    local packages
    packages=$(set -o pipefail; awk '
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
        pkg = ver = indent = ""
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
    # The first property line sets the indentation of the entry fields: a
    # dependency named "version" sits deeper, under dependencies:.
    pkg != "" && indent == "" && match($0, /^[[:space:]]+[^[:space:]]/) { indent = substr($0, 1, RLENGTH - 1) }
    # Classic: version "x.y.z"   Berry: version: x.y.z
    /^[[:space:]]+version[[:space:]:]/ && pkg != "" && ver == "" && substr($0, 1, length(indent) + 1) == indent "v" {
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
    ' "$lock_text" 2>/dev/null | sort -u) || { report_parser_failure "$lockfile"; return 0; }

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
    packages=$(set -o pipefail; awk '
    BEGIN { in_packages=0 }
    /^packages:/ { in_packages=1; next }
    /^[a-zA-Z]/ && !/^[[:space:]]/ && in_packages { in_packages=0 }
    in_packages {
        line = $0
        # A package installed from a tarball URL or git names no version in
        # its key ("xlsx@https://...", or before pnpm 9 a host path such as
        # "github.com/owner/repo/<sha>" without even the name): pnpm records
        # them in the name: and version: fields of the block.
        if (want_fields && line ~ /^    (name|version):[[:space:]]*[^[:space:]]/) {
            value = line
            sub(/^    [a-z]+:[[:space:]]*/, "", value)
            gsub(/[\047"[:space:]]/, "", value)
            if (line ~ /^    name:/) field_name = value
            else field_version = value
            if (field_name != "" && field_version != "") {
                print field_name "|" field_version
                want_fields = 0
            }
            next
        }
        # Only package-map keys, never nested dependency metadata.
        if (line !~ /^  [^[:space:]].*:[[:space:]]*$/) next
        want_fields = 0; field_name = ""; field_version = ""
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
            want_fields = 1
            field_name = substr(line, 1, at)
            next
        }

        # name@version, split at the first "@" after a leading scope marker.
        if (at > 0 && substr(line, at + 2) ~ /^[0-9]/) {
            print substr(line, 1, at) "|" substr(line, at + 2)
            next
        }

        # The key names no version: read the name: and version: fields.
        want_fields = 1
    }
    ' "$lockfile" 2>/dev/null | sort -u) || { report_parser_failure "$lockfile"; return 0; }

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

# bun.lockb is binary: `bun <file>` prints it as a yarn v1 lockfile (bun
# 1.1 to 1.4 at least). Convert every discovered bun.lockb once, before the
# feeds are pre-filtered on the project's names, into BUN_LOCKB_TEXT. bun runs
# from an empty directory so no project bunfig.toml applies. A bun.lockb that
# cannot be converted is reported as not scanned and makes the scan
# incomplete; one beside a bun.lock is skipped (bun uses bun.lock).
prepare_bun_lockbs() {
    case "$LOCKFILES" in *bun.lockb*) ;; *) return 0 ;; esac
    local lf abs text neutral="" reason
    while IFS= read -r lf; do
        [ "${lf##*/}" = bun.lockb ] && [ -r "$lf" ] || continue
        [ ! -f "${lf%/*}/bun.lock" ] || continue
        reason=""
        if ! command -v bun >/dev/null 2>&1; then
            reason="bun.lockb is binary and bun is not installed to read it"
        else
            case "$lf" in /*) abs="$lf" ;; *) abs="$PWD/$lf" ;; esac
            if [ -z "$neutral" ]; then
                neutral=$(mktemp -d) && register_temp_dir "$neutral" || neutral="/"
            fi
            if text=$(mktemp); then
                register_temp_file "$text"
                if (cd "$neutral" && bun "$abs") > "$text" 2>/dev/null && grep -q '^# yarn lockfile v1' "$text"; then
                    BUN_LOCKB_TEXT["$lf"]="$text"
                else
                    reason="bun could not print it as a yarn lockfile"
                fi
            else
                reason="no temporary file for its text form"
            fi
        fi
        if [ -n "$reason" ]; then
            UNSUPPORTED_FILES+=("$lf")
            INCOMPLETE_REASONS+=("$lf was not scanned: $reason")
        fi
    done <<< "$LOCKFILES"
}

# Function to analyze a bun.lockb file through its text form (see
# prepare_bun_lockbs).
analyze_bun_lockb() {
    local lockfile="$1" eco="${2:-npm}"
    if [ -n "${BUN_LOCKB_TEXT[$lockfile]+x}" ]; then
        analyze_yarn_lock "$lockfile" "$eco" "${BUN_LOCKB_TEXT[$lockfile]}"
        return 0
    fi
    # Reported here: no "no package could be read" warning on top.
    LOCKFILE_SKIPPED=1
    if [ -f "${lockfile%/*}/bun.lock" ]; then
        echo "   ⏩ [$lockfile] Skipped: bun uses the bun.lock beside it"
    elif ! command -v bun >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  [$lockfile] Not scanned: bun.lockb is binary; install bun (https://bun.sh) to read it, or run bun install --save-text-lockfile to write bun.lock${NC}"
    else
        echo -e "${YELLOW}⚠️  [$lockfile] Not scanned: bun could not print it as a yarn lockfile${NC}"
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
    packages=$(set -o pipefail; awk '
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
    # Package entries: "key": ["pkg@version", ...]. Only the first element of
    # an entry names the installed version: the dependencies and
    # peerDependencies objects that follow it list requested specs
    # ("minimist": "0.0.8" under mkdirp), never installed versions.
    match($0, /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*\["[^"]+@[0-9][^"]*"/) {
        temp = substr($0, RSTART, RLENGTH)
        sub(/^.*\["/, "", temp)
        sub(/"$/, "", temp)
        # Split at last @
        idx = 0
        for (i=length(temp); i>0; i--) {
            if (substr(temp, i, 1) == "@") { idx = i; break }
        }
        if (idx > 1) print substr(temp, 1, idx-1) "|" substr(temp, idx+1)
    }
    ' "$lockfile" 2>/dev/null | sort -u) || { report_parser_failure "$lockfile"; return 0; }

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

    # Only the keys of the npm package map name installed npm packages:
    # "npm" (lockfile v4/v5), "packages"."npm" (v3) and "npm"."packages" (v2).
    # jsr packages, specifiers and remote URLs sit in sibling sections and
    # are not npm packages. json_structural_lines makes the layout (pretty or
    # compact) irrelevant: an object opens at the end of its record.
    local packages
    packages=$(set -o pipefail; json_structural_lines "$lockfile" 2>/dev/null | awk '
    {
        rec = $0
        sub(/[[:space:]]+$/, "", rec)
        if (rec == "}" || rec == "]") { if (depth > 0) depth--; next }
        last = substr(rec, length(rec))
        if (last != "{" && last != "[") next
        key = ""
        if (match(rec, /^[[:space:]]*"[^"]*"[[:space:]]*:/)) {
            key = substr(rec, RSTART, RLENGTH)
            sub(/^[[:space:]]*"/, "", key)
            sub(/"[[:space:]]*:$/, "", key)
        }
        in_npm = (depth == 2 && stack[2] == "npm") ||
            (depth == 3 && stack[2] == "packages" && stack[3] == "npm") ||
            (depth == 3 && stack[2] == "npm" && stack[3] == "packages")
        # Name/version split at the first "@" after the scope marker.
        # Package names may contain "_" (string_decoder): only the
        # version carries the "_peer@x" suffix, so strip it there.
        at_idx = index(substr(key, 2), "@")
        if (in_npm && last == "{" && at_idx > 0) {
            pkg_name = substr(key, 1, at_idx)
            version = substr(key, at_idx + 2)
            sub(/_.*/, "", version)
            if (version ~ /^[0-9]/) print pkg_name "|" version
        }
        stack[++depth] = key
    }
    ' | sort -u) || { report_parser_failure "$lockfile"; return 0; }

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
