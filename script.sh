#!/usr/bin/env bash
# GENERATED FILE NOTICE: script.sh is built from src/ by ./build.sh — edit src/, not script.sh.

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

# Plain POSIX syntax up to the version check, so `sh script.sh` gets this
# message instead of a parse error.
case "${BASH_VERSION:-}" in
    ""|[0-3].*)
        printf '%s\n' 'Error: package-checker requires Bash 4 or newer (macOS: brew install bash).' >&2
        exit 2 ;;
esac
set -e

# Exit codes: 0 = no vulnerable package, 1 = vulnerable packages found,
# EXIT_ERROR = the scan could not run or complete (bad usage, unreadable or
# empty data, unexpected failure). CI treats any non-zero code as a failure.
EXIT_ERROR=2

# Byte-wise string comparison and character classes: version ordering
# ([[ a < b ]]), awk ranges and sort must not depend on the user's locale
# (5.0.0-beta1 vs 5.0.0-RC1 orders differently under fr_FR and C).
export LC_ALL=C

# Version - automatically updated by release workflow
# Last release: https://github.com/maxgfr/package-checker.sh/releases
# NOTE: this exact 'VERSION="..."' format is sed-matched by .releaserc.json — do not reformat.
VERSION="1.14.3"

# Default configuration
CONFIG_FILE=".package-checker.config.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
DATA_SOURCES=()
LOADED_SOURCE_COUNT=0
FOUND_VULNERABLE=0
VULNERABLE_PACKAGES=()

# Pre-built vulnerability lookup tables (for O(1) lookup)
declare -A VULN_EXACT_LOOKUP      # VULN_EXACT_LOOKUP[package]="ver1|ver2|..."
declare -A VULN_RANGE_LOOKUP      # VULN_RANGE_LOOKUP[package]="range1|range2|..."
declare -A VULN_METADATA_SEVERITY # VULN_METADATA_SEVERITY[package@version OR package]="critical|high|medium|low"
declare -A VULN_METADATA_GHSA     # VULN_METADATA_GHSA[package@version OR package]="GHSA-xxxx-xxxx-xxxx"
declare -A VULN_METADATA_CVE      # VULN_METADATA_CVE[package@version OR package]="CVE-YYYY-NNNNN"
declare -A VULN_METADATA_SOURCE   # VULN_METADATA_SOURCE[package@version OR package]="ghsa|osv|custom"
declare -A VULN_ADVISORIES        # VULN_ADVISORIES[package@version]="sev;ghsa;cve;src||sev;ghsa;cve;src" (all matching advisories)
declare -A VULN_METADATA_FIX      # VULN_METADATA_FIX[package:range]="fix_version" (upper bound from range)
declare -A VULN_RECORDS           # lookup key -> newline-separated advisory records

# Configuration defaults (can be overridden by config file)
CONFIG_IGNORE_PATHS=("node_modules" ".yarn" ".git" "vendor")
CONFIG_DEPENDENCY_TYPES=("dependencies" "devDependencies" "optionalDependencies")
CONFIG_ECOSYSTEMS=""  # optional feed-loading override from config (options.ecosystems)
CONFIG_RUNTIME_CHECK=true  # options.runtime_check (--no-runtime-check overrides)

# Project files that could not be read (an incomplete scan is never clean)
UNREADABLE_FILE_COUNT=0

# Ecosystem registry lookup tables — derived from ECOSYSTEM_REGISTRY by
# build_ecosystem_tables() (see src/50-ecosystems/01-registry.sh)
declare -A LOCKFILE_PARSER   # LOCKFILE_PARSER[basename]="analyze_fn"
declare -A LOCKFILE_ECO      # LOCKFILE_ECO[basename]="purl-type"
declare -A LOCKFILE_ALIAS    # LOCKFILE_ALIAS[basename]="type-alias"
KNOWN_LOCKFILE_ALIASES=""    # space-separated unique alias list (validation + help)

# Ecosystems detected in the scanned project (eco -> 1); drives default-feed loading
declare -A DETECTED_ECOSYSTEMS

# govulncheck call analysis of Go findings (--go-reachability)
declare -A VULN_REACHABILITY      # VULN_REACHABILITY[dir|golang:module@version]="called|not called"

# CycloneDX SBOMs given with --sbom (path -> 1), scanned as project inventories
declare -A SBOM_FILES
# Syntax validation for JSON inputs; scan-time code must not require jq.
# Stream tokens through a small grammar stack. Repeated indexing into a growing
# whole-document string becomes quadratic with some awk implementations.
json_is_valid() {
    printf '%s\n' "$1" | json_is_valid_file /dev/stdin
}

# Same check on a file, read directly by awk (no copy into a shell variable).
json_is_valid_file() {
    LC_ALL=C awk '
    function take_value() {
        if (state[depth] != "value" && state[depth] != "value-or-end") return 0
        state[depth] = depth ? "comma-or-end" : "done"
        return 1
    }
    function finish_token() {
        if (token == "") return 1
        if (token !~ /^(true|false|null)$/ &&
            token !~ /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/) return 0
        token = ""
        return take_value()
    }
    function character(c) {
        if (quoted) {
            if (c ~ /[\001-\037]/) return 0
            if (unicode) {
                if (c !~ /^[0-9a-fA-F]$/) return 0
                unicode--
            } else if (escaped) {
                escaped = 0
                if (c == "u") unicode = 4
                else if (c !~ /^["\\\/bfnrt]$/) return 0
            } else if (c == "\\") escaped = 1
            else if (c == "\"") {
                quoted = 0
                if (key_string) state[depth] = "colon"
                else if (!take_value()) return 0
            }
            return 1
        }
        if (c !~ /^[ \t\r\n{}\[\],:"]$/) { token = token c; return 1 }
        if (!finish_token()) return 0
        if (c ~ /^[ \t\r\n]$/) return 1
        if (c == "\"") {
            key_string = (state[depth] == "key" || state[depth] == "key-or-end")
            if (!key_string && state[depth] != "value" && state[depth] != "value-or-end") return 0
            quoted = 1
        } else if (c == "{" || c == "[") {
            if (!take_value() || depth >= 128) return 0
            kind[++depth] = c
            state[depth] = c == "{" ? "key-or-end" : "value-or-end"
        } else if (c == "}" || c == "]") {
            if (!depth || (c == "}" && kind[depth] != "{") ||
                (c == "]" && kind[depth] != "[")) return 0
            if (state[depth] != "comma-or-end" && state[depth] != "key-or-end" &&
                state[depth] != "value-or-end") return 0
            depth--
        } else if (c == ":") {
            if (state[depth] != "colon") return 0
            state[depth] = "value"
        } else if (c == ",") {
            if (!depth || state[depth] != "comma-or-end") return 0
            state[depth] = kind[depth] == "{" ? "key" : "value"
        }
        return 1
    }
    BEGIN { depth = 0; state[0] = "value" }
    # A UTF-8 byte order mark is an encoding marker, not JSON.
    NR == 1 && substr($0, 1, 3) == "\357\273\277" { $0 = substr($0, 4) }
    {
        # Most pretty-printed lockfile records contain short, unescaped tokens.
        # Consume whole strings/numbers there, keeping the bounded byte path for
        # escapes and long compact records. Both paths use the same grammar.
        if (length($0) < 4096 && $0 !~ /\\/) {
            rest = $0
            while (length(rest)) {
                if (match(rest, /^[ \t\r]+/)) {
                    rest = substr(rest, RLENGTH + 1)
                } else if (match(rest, /^"[^"\001-\037]*"/)) {
                    rest = substr(rest, RLENGTH + 1)
                    if (state[depth] == "key" || state[depth] == "key-or-end") state[depth] = "colon"
                    else if (!take_value()) { invalid = 1; exit }
                } else if (match(rest, /^[^ \t\r{}\[\],:"]+/)) {
                    token = substr(rest, 1, RLENGTH)
                    rest = substr(rest, RLENGTH + 1)
                    if (!finish_token()) { invalid = 1; exit }
                } else {
                    if (!character(substr(rest, 1, 1))) { invalid = 1; exit }
                    rest = substr(rest, 2)
                }
            }
            if (!character("\n")) { invalid = 1; exit }
            next
        }
        # Bound memory for compact single-line lockfiles as well.
        for (offset = 1; offset <= length($0); offset += 4096) {
            size = split(substr($0, offset, 4096), chars, "")
            for (i = 1; i <= size; i++) {
                if (!character(chars[i])) { invalid = 1; exit }
            }
        }
        if (!character("\n")) { invalid = 1; exit }
    }
    END { exit (invalid || quoted || depth || !finish_token() || state[0] != "done") }
    ' "$1"
}
# ============================================================================
# Pure Bash JSON Parser Functions (no jq dependency)
# ============================================================================

# Escape special regex characters in a string
escape_regex() {
    local str="$1"
    printf '%s' "$str" | sed 's/[.[\*^$()+?{|\\]/\\&/g'
}

# Get a simple string value from JSON by key (top-level only)
# Usage: json_get_value "$json" "key"
json_get_value() {
    local json="$1"
    local key="$2"
    local escaped_key=$(escape_regex "$key")
    # Match "key": "value" or "key": value (for numbers/booleans)
    local result=$(echo "$json" | grep -oE "\"$escaped_key\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+|true|false|null)" | head -1)
    if [ -n "$result" ]; then
        echo "$result" | sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*//' | sed 's/^"//;s/"$//'
    fi
}

# Get array length from JSON (for simple arrays at top level)
# Usage: json_array_length "$json"
json_array_length() {
    local json="$1"
    # Count elements by counting commas + 1 (or 0 if empty)
    local trimmed=$(echo "$json" | tr -d '\n\r\t ' | sed 's/^\[//;s/\]$//')
    if [ -z "$trimmed" ] || [ "$trimmed" = "[]" ]; then
        echo "0"
        return
    fi
    # Count top-level commas (not inside nested structures)
    local count=1
    local depth=0
    local in_string=false
    local prev_char=""
    local i=0
    local len=${#trimmed}
    
    while [ $i -lt $len ]; do
        local char="${trimmed:$i:1}"
        if [ "$in_string" = true ]; then
            if [ "$char" = '"' ] && [ "$prev_char" != "\\" ]; then
                in_string=false
            fi
        else
            case "$char" in
                '"') in_string=true ;;
                '[' | '{') depth=$((depth + 1)) ;;
                ']' | '}') depth=$((depth - 1)) ;;
                ',') [ $depth -eq 0 ] && count=$((count + 1)) ;;
            esac
        fi
        prev_char="$char"
        i=$((i + 1))
    done
    echo "$count"
}

# Get array element at index from JSON array
# Usage: json_array_get "$json_array" index
json_array_get() {
    local json="$1"
    local index="$2"
    local trimmed=$(echo "$json" | tr -d '\n\r\t' | sed 's/^[[:space:]]*\[//;s/\][[:space:]]*$//')
    
    local current=0
    local depth=0
    local in_string=false
    local prev_char=""
    local start=0
    local i=0
    local len=${#trimmed}
    
    while [ $i -lt $len ]; do
        local char="${trimmed:$i:1}"
        if [ "$in_string" = true ]; then
            if [ "$char" = '"' ] && [ "$prev_char" != "\\" ]; then
                in_string=false
            fi
        else
            case "$char" in
                '"') in_string=true ;;
                '[' | '{') depth=$((depth + 1)) ;;
                ']' | '}') depth=$((depth - 1)) ;;
                ',')
                    if [ $depth -eq 0 ]; then
                        if [ $current -eq $index ]; then
                            echo "${trimmed:$start:$((i - start))}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                            return
                        fi
                        current=$((current + 1))
                        start=$((i + 1))
                    fi
                    ;;
            esac
        fi
        prev_char="$char"
        i=$((i + 1))
    done
    
    # Last element
    if [ $current -eq $index ]; then
        echo "${trimmed:$start}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
    fi
}

# Get nested object value from JSON
# Usage: json_get_object "$json" "key"
json_get_object() {
    local json="$1"
    local key="$2"
    
    # Flatten JSON to single line and extract object
    local flat=$(echo "$json" | tr '\n' ' ' | tr -s ' ')
    
    # Find position of key and extract content after it
    # Use Python-like approach with awk
    echo "$flat" | awk -v key="\"$key\"" '
    {
        # Find the key
        idx = index($0, key)
        if (idx == 0) { print "{}"; exit }
        
        # Get everything after the key
        rest = substr($0, idx + length(key))
        
        # Skip whitespace and colon
        match(rest, /^[[:space:]]*:[[:space:]]*/)
        rest = substr(rest, RLENGTH + 1)
        
        # Check first character
        first = substr(rest, 1, 1)
        if (first != "{" && first != "[") { print "{}"; exit }
        
        # Count brackets to find the end
        depth = 0
        in_str = 0
        result = ""
        n = length(rest)
        
        for (i = 1; i <= n; i++) {
            c = substr(rest, i, 1)
            result = result c
            
            if (in_str) {
                if (c == "\"" && substr(rest, i-1, 1) != "\\") in_str = 0
            } else {
                if (c == "\"") in_str = 1
                else if (c == "{" || c == "[") depth++
                else if (c == "}" || c == "]") {
                    depth--
                    if (depth == 0) { print result; exit }
                }
            }
        }
        print "{}"
    }'
}

# Get array from JSON object by key
# Usage: json_get_array "$json" "key"
json_get_array() {
    local json="$1"
    local key="$2"
    local result=$(json_get_object "$json" "$key")
    # Return empty array if result is empty object or invalid
    if [ -z "$result" ] || [ "$result" = "{}" ]; then
        echo "[]"
    else
        echo "$result"
    fi
}
# Put structural JSON delimiters on separate records without changing strings.
# Line-oriented lockfile readers can then handle compact or pretty JSON alike.
json_structural_lines() {
    awk '
    # A UTF-8 byte order mark is an encoding marker, not JSON.
    NR == 1 && substr($0, 1, 3) == "\357\273\277" { $0 = substr($0, 4) }
    function flush() {
        if (buffer ~ /[^[:space:]]/) print buffer
        buffer = ""
    }
    {
        # Generated pretty JSON normally has one unescaped scalar per line.
        # Preserve the existing record whitespace while skipping its byte loop.
        if (!quoted && buffer !~ /[^[:space:]]/ &&
            $0 ~ /^[[:space:]]*"[^"\\]*"[[:space:]]*:[[:space:]]*("[^"\\]*"|true|false|null|-?[0-9.]+),?$/) {
            buffer = buffer $0
            if (substr(buffer, length(buffer), 1) == ",") {
                buffer = substr(buffer, 1, length(buffer) - 1)
                flush()
            }
            buffer = buffer " "
            next
        }
        # BSD awk scans to substr offsets in multibyte records. Bound the
        # inner offsets even when the entire lockfile occupies one long line.
        record_size = length($0)
        for (offset = 1; offset <= record_size; offset += 4096) {
            chunk = substr($0, offset, 4096)
            chunk_size = length(chunk)
            for (i = 1; i <= chunk_size; i++) {
                c = substr(chunk, i, 1)
            if (quoted) {
                buffer = buffer c
                if (escaped) escaped = 0
                else if (c == "\\") escaped = 1
                else if (c == "\"") quoted = 0
            } else if (c == "\"") {
                quoted = 1
                buffer = buffer c
            } else if (c == "{" || c == "[") {
                buffer = buffer c
                flush()
            } else if (c == "}" || c == "]") {
                flush()
                print c
            } else if (c == ",") {
                flush()
            } else {
                buffer = buffer c
            }
            }
        }
        if (!quoted) buffer = buffer " "
    }
    END { flush() }
    ' "$1"
}

# ============================================================================
# End of JSON Parser Functions
# ============================================================================

# Show version information
show_version() {
    echo "package-checker.sh version $VERSION"
    echo ""
    echo "Scan project dependencies (npm, PyPI, Go, Maven, Cargo, RubyGems, Composer, NuGet,"
    echo "Pub, Hex, Swift, GitHub Actions) for known vulnerable versions."
    echo "Repository: https://github.com/maxgfr/package-checker.sh"
    exit 0
}

# Help message
show_help() {
    cat << EOF
Usage: $0 [PATH] [OPTIONS]

Scan project dependencies (npm, PyPI, Go, Maven, Cargo, RubyGems, Composer, NuGet,
Pub, Hex, Swift, GitHub Actions) for known vulnerable versions, using the built-in
GHSA/OSV feeds or your own data sources. The Node.js and PHP versions the project
targets (.nvmrc, Docker base image, composer.json platform...) are checked too.

ARGUMENTS:
    PATH                    Directory to scan (default: current directory)

OPTIONS:
    -h, --help              Show this help message
    --help-ai               Show AI help menu
    --help-ai prompt        Output the AI system prompt (prompt.md)
    --help-ai doc           Output the full AI guide (docs/ai-guide.md)
    -v, --version           Show version information
    -s, --source SOURCE     Data source path or URL (can be used multiple times)
    --default-source-ghsa   Use default GHSA source (script dir, brew, /app/data/, ./data/, then GitHub)
    --default-source-osv    Use default OSV source (script dir, brew, /app/data/, ./data/, then GitHub)
    --default-source-ghsa-osv        Use both default GHSA and OSV sources (recommended)
    -f, --format FORMAT     Format of the preceding -s source: json, csv, purl, sarif,
                            sbom-cyclonedx or trivy-json (default: auto-detected from
                            the file extension, json when unknown)
    -c, --config FILE       Path to configuration file (default: .package-checker.config.json);
                            its options always apply, its sources only when no source
                            is given on the command line
    --no-config             Skip the default configuration file
    --csv-columns COLS      CSV columns of the preceding -s source (e.g., "1,2" or "name,versions")
    --package-name NAME     Check vulnerability for a specific package name
    --package-version VER   Check specific version (requires --package-name)
    --ecosystem ECO         Ecosystem for --package-name (default: npm). One of:
                            npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions,
                            runtime (Node.js / PHP: --package-name node --ecosystem runtime)
    --export-json [FILE]    Export results to JSON (FILE optional, default: vulnerabilities.json)
    --export-csv [FILE]     Export results to CSV (FILE optional, default: vulnerabilities.csv)
    --github-org ORG        GitHub organization to fetch package.json files from
    --github-repo REPO      GitHub repository to fetch package.json files from (format: owner/repo)
    --github-token TOKEN    GitHub personal access token (or use GITHUB_TOKEN env var)
    --github-output DIR     Output directory for fetched packages (default: ./packages)
    --github-only           Only fetch packages from GitHub, don't analyze local files
    --create-multiple-issues Create one GitHub issue per vulnerable package (requires --github-token)
    --create-single-issue   Create a single GitHub issue with all vulnerabilities (requires --github-token)
    --fetch-all DIR         Fetch GHSA + OSV feeds for ALL ecosystems to DIR (default: data)
    --fetch-osv [ECOS]      Fetch OSV feeds; optional comma list of ecosystems (default: all)
    --fetch-ghsa [ECOS]     Fetch GHSA feeds (single clone); optional comma list (default: all)
    --fetch-runtime [DIR]   Fetch the Node.js / PHP runtime feed (OSV Bitnami) to
                            DIR/osv-runtime.purl (default: data)
    --only-package-json     Scan only package.json files (skip lockfiles)
    --only-lockfiles        Scan only lockfiles (skip package.json files)
    --lockfile-types TYPES  Comma-separated list of lockfile types to scan
                            (npm, yarn, pnpm, bun, deno, rust, go, python, ruby, php,
                            maven, nuget, dart, hex, swift, actions). "actions" scans
                            GitHub Actions workflow files (.github/workflows/*.yml).
                            Example: --lockfile-types yarn,npm
    --ecosystems ECOS       Comma-separated ecosystems to load default feeds for,
                            overriding auto-detection. Accepts lockfile-type aliases
                            (npm, yarn, pnpm, bun, deno, rust, go, python, ruby, php,
                            maven, nuget, dart, hex, swift, actions) or purl types
                            (npm, pypi, golang, cargo, githubactions, ...).
                            Example: --ecosystems npm
    --sbom FILE             Also scan the components of a CycloneDX JSON SBOM, like a
                            lockfile (can be used multiple times). Use it for Maven
                            transitive dependencies, which pom.xml does not list:
                            mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
    --go-reachability       Annotate each Go finding "called" or "not called" with
                            govulncheck, when it is installed (one run per go.mod).
                            The exit code does not change.
    --no-runtime-check      Do not check the Node.js / PHP versions the project targets
                            (.nvmrc, .node-version, .php-version, .tool-versions,
                            package.json engines/volta, composer.json/composer.lock
                            platform, Dockerfile FROM node:/php:, workflow
                            node-version:/php-version:). An exact version is a
                            finding; a release line or a range only warns.
    --include-gitignored    Also scan git-ignored lockfiles and manifests (skipped and
                            listed by default)

EXIT CODES:
    0   No vulnerable package found
    1   Vulnerable packages found
    2   Error: invalid usage, unreadable or empty data source, failed scan

EXAMPLES:
    # Scan current directory with default sources (recommended)
    $0 --default-source-ghsa-osv

    # Scan specific directory
    $0 ./my-project --default-source-osv
    $0 /absolute/path/to/project --default-source-ghsa-osv

    # Use configuration file
    $0 --config .package-checker.config.json

    # Use custom source (-f/--csv-columns qualify the -s right before them)
    $0 --source https://example.com/vulns.json
    $0 --source ./vulns.csv -f csv --csv-columns "name,versions"

    # GitHub organization scan
    $0 --github-org myorg --github-token ghp_xxxx --default-source-ghsa-osv

    # Check specific package
    $0 --package-name express --package-version 4.17.1

    # Fetch vulnerability feeds (all ecosystems)
    $0 --fetch-all data

    # Fetch feeds for specific ecosystems only
    $0 --fetch-osv pypi,golang
    $0 --fetch-ghsa cargo

    # Scan a Maven project with its transitive dependencies
    $0 --sbom target/bom.json --default-source-ghsa-osv

    # Scan only lockfiles in specific directory
    $0 ./subfolder --only-lockfiles --lockfile-types yarn,npm

For configuration file format, use: $0 --help format
EOF
    exit 0
}

# Show configuration format help
show_format_help() {
    cat << 'EOF'
CONFIGURATION FILE FORMAT (.package-checker.config.json):
{
  "sources": [
    {
      "source": "https://example.com/vulns.json",
      "format": "json",
      "name": "My Vulnerability List"
    },
    {
      "source": "https://example.com/vulns.csv",
      "format": "csv",
      "columns": "name,versions",
      "name": "CSV Vulnerabilities"
    }
  ],
  "github": {
    "org": "my-organization",
    "repo": "owner/repo",
    "token": "ghp_xxxx",
    "output": "./packages"
  },
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git"],
    "dependency_types": ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"],
    "runtime_check": true
  }
}

DATA FORMATS:

JSON format (object with package names as keys):
{
  "package-name": {
    "versions": ["1.0.0", "2.0.0"]
  }
}

CSV format (default columns: package,version; the first line is a header
unless its version field looks like a version or a range):
name,versions
package-name,1.0.0
package-name,2.0.0
another-package,">=3.0.0 <3.2.1"

CSV format with custom columns:
name,versions,sources
express,4.16.0,"datadog, helixguard"
lodash,4.17.19,"koi, reversinglabs"

Use --csv-columns to specify which columns to use:
--csv-columns "1,2"     # Use columns 1 and 2 (name, versions)
--csv-columns "name,versions"  # Use column names
EOF
    exit 0
}

# GitHub raw base URL for AI docs
GITHUB_RAW_BASE="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main"

# Resolve an AI doc file: try local paths first, then fetch from GitHub
# Usage: resolve_ai_doc <relative-path>
# Output: file content to stdout
resolve_ai_doc() {
    local file_path="$1"
    local script_dir=""

    # Try to find the script's own directory
    if [ -n "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi

    # 1. Local relative to script location
    if [ -n "$script_dir" ] && [ -f "$script_dir/$file_path" ]; then
        cat "$script_dir/$file_path"
        return 0
    fi

    # 2. Local relative to cwd
    if [ -f "./$file_path" ]; then
        cat "./$file_path"
        return 0
    fi

    # 3. Homebrew prefix
    local brew_prefix=""
    if command -v brew &> /dev/null; then
        brew_prefix="$(brew --prefix 2>/dev/null)/share/package-checker"
        if [ -f "$brew_prefix/$file_path" ]; then
            cat "$brew_prefix/$file_path"
            return 0
        fi
    fi

    # 4. Docker path
    if [ -f "/app/$file_path" ]; then
        cat "/app/$file_path"
        return 0
    fi

    # 5. Fetch from GitHub
    local url="${GITHUB_RAW_BASE}/${file_path}"
    local content
    if content=$(curl -fsSL "$url" 2>/dev/null) && [ -n "$content" ]; then
        echo "$content"
        return 0
    fi

    return 1
}

# Show AI help menu or subcommand
show_ai_help() {
    local subcommand="${1:-}"

    case "$subcommand" in
        prompt)
            echo -e "${BLUE}package-checker.sh — AI System Prompt${NC}"
            echo -e "${BLUE}======================================${NC}"
            echo ""
            echo -e "${YELLOW}Source: ${GITHUB_RAW_BASE}/prompt.md${NC}"
            echo ""
            local content
            if content=$(resolve_ai_doc "prompt.md"); then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load prompt.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/prompt.md"
                exit "$EXIT_ERROR"
            fi
            ;;
        doc)
            echo -e "${BLUE}package-checker.sh — AI Guide (Full Reference)${NC}"
            echo -e "${BLUE}================================================${NC}"
            echo ""
            echo -e "${YELLOW}Source: ${GITHUB_RAW_BASE}/docs/ai-guide.md${NC}"
            echo ""
            local content
            if content=$(resolve_ai_doc "docs/ai-guide.md"); then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load docs/ai-guide.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/docs/ai-guide.md"
                exit "$EXIT_ERROR"
            fi
            ;;
        *)
            cat << EOF
AI-Assisted Usage for package-checker.sh
=========================================

Use these commands to get AI-ready documentation:

  $(basename "$0") --help-ai prompt    Output the system prompt (prompt.md)
                                  Paste this into any AI assistant as context.

  $(basename "$0") --help-ai doc       Output the full AI guide (docs/ai-guide.md)
                                  Complete schemas, validation rules, and recipes.

One-liner to inject into an AI conversation:

  $(basename "$0") --help-ai prompt | pbcopy       # macOS: copy to clipboard
  $(basename "$0") --help-ai prompt | xclip        # Linux: copy to clipboard
  $(basename "$0") --help-ai prompt > context.md   # Save to file and attach

GitHub URLs (always up-to-date):

  Prompt:  ${GITHUB_RAW_BASE}/prompt.md
  Guide:   ${GITHUB_RAW_BASE}/docs/ai-guide.md

EOF
            ;;
    esac
    exit 0
}

# Check that the required tools are installed (default: curl, used to
# download remote sources). Feed generation also needs jq and friends.
check_dependencies() {
    local tool
    [ $# -gt 0 ] || set -- curl
    for tool in "$@"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "❌ Error: '$tool' must be installed to run this command"
            exit "$EXIT_ERROR"
        fi
    done
}

# Temporary files removed when the script exits, whatever the exit path.
PC_TEMP_FILES=()
PC_CLEANUP_TRAP=false
pc_cleanup_temp_files() {
    [ ${#PC_TEMP_FILES[@]} -eq 0 ] || rm -f -- "${PC_TEMP_FILES[@]}"
}
# Register a temp file for cleanup. The EXIT trap is installed once and keeps
# any EXIT trap already set (it runs after the cleanup).
register_temp_file() {
    PC_TEMP_FILES+=("$1")
    [ "$PC_CLEANUP_TRAP" = true ] && return 0
    PC_CLEANUP_TRAP=true
    local previous
    previous=$(trap -p EXIT)
    if [ -n "$previous" ]; then
        eval "set -- $previous"   # trap -- 'command' EXIT
        trap "pc_cleanup_temp_files; $3" EXIT
    else
        trap pc_cleanup_temp_files EXIT
    fi
}

# GitHub API functions
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_ORG="${GITHUB_ORG:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_OUTPUT_DIR="${GITHUB_OUTPUT_DIR:-./packages}"
GITHUB_ONLY=false
GITHUB_RATE_LIMIT_DELAY=2
CREATE_GITHUB_ISSUE=false
CREATE_SINGLE_ISSUE=false

# Make a GitHub API request with automatic retry on rate limit. A 403/429
# rate-limit answer waits until the time GitHub gives (Retry-After or
# x-ratelimit-reset), capped by GITHUB_RATE_LIMIT_MAX_WAIT seconds.
GITHUB_RATE_LIMIT_MAX_WAIT="${GITHUB_RATE_LIMIT_MAX_WAIT:-900}"
github_request() {
    local url="$1"
    local max_retries=3
    local attempt=1
    local response http_code headers wait_time value

    while [ $attempt -le $max_retries ]; do
        headers=$(mktemp) || return 1
        register_temp_file "$headers"
        if ! response=$(curl -sS --connect-timeout 10 --max-time 60 -D "$headers" -w "\n%{http_code}" \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: package-checker-script" \
            "$url"); then
            rm -f -- "$headers"
            echo "Error: Unable to reach GitHub API" >&2
            return 1
        fi

        http_code="${response##*$'\n'}"
        response="${response%$'\n'*}"

        if [ "$http_code" = "200" ]; then
            rm -f -- "$headers"
            echo "$response"
            return 0
        fi

        # Handle rate limiting (403 or 429)
        if { [ "$http_code" = 429 ] || { [ "$http_code" = 403 ] &&
            { [[ "$response" == *"rate limit"* ]] || grep -qi '^x-ratelimit-remaining:[[:space:]]*0' "$headers"; }; }; } &&
            [ $attempt -lt $max_retries ]; then
            wait_time=60
            value=$(awk 'tolower($1) == "retry-after:" { gsub(/\r/, "", $2); print $2 }' "$headers")
            if [[ "$value" =~ ^[0-9]+$ ]]; then
                wait_time=$value
            else
                value=$(awk 'tolower($1) == "x-ratelimit-reset:" { gsub(/\r/, "", $2); print $2 }' "$headers")
                if [[ "$value" =~ ^[0-9]+$ ]]; then
                    wait_time=$(( value - $(date +%s) + 1 ))
                    [ "$wait_time" -ge 1 ] || wait_time=1
                fi
            fi
            rm -f -- "$headers"
            if [ "$wait_time" -gt "$GITHUB_RATE_LIMIT_MAX_WAIT" ]; then
                echo -e "${RED}❌ GitHub rate limit resets in ${wait_time}s (more than ${GITHUB_RATE_LIMIT_MAX_WAIT}s); giving up${NC}" >&2
                return 1
            fi
            echo -e "${YELLOW}⚠️  Rate limit hit, waiting ${wait_time}s before retry ($attempt/$max_retries)...${NC}" >&2
            sleep "$wait_time"
            attempt=$((attempt + 1))
            continue
        fi
        rm -f -- "$headers"

        # Non-retryable error or max retries reached
        echo -e "${RED}❌ GitHub API error ($http_code): $response${NC}" >&2
        return 1
    done

    return 1
}

# Get all repositories from a GitHub organization
# OPTIMIZED: Returns newline-separated list of "name|full_name" instead of JSON
get_github_repositories() {
    echo -e "${BLUE}🔍 Fetching repositories for organization: $GITHUB_ORG${NC}" >&2
    
    local all_repos=""
    local page=1
    local per_page=100
    
    while true; do
        local url="https://api.github.com/orgs/${GITHUB_ORG}/repos?page=${page}&per_page=${per_page}"
        local repos
        
        repos=$(github_request "$url") || return 1
        
        # FIXED: Use grep -o | wc -l to count occurrences correctly (grep -c counts lines, not occurrences)
        local count=$(echo "$repos" | grep -o '"full_name"' | wc -l | tr -d ' ')
        
        if [ "$count" -eq 0 ]; then
            break
        fi
        
        # OPTIMIZED: Extract name and full_name pairs using grep/sed
        # Format: name|full_name (one per line)
        local repo_pairs
        repo_pairs=$(echo "$repos" | tr '\n' ' ' | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]*"[^}]*"full_name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            sed 's/"name"[[:space:]]*:[[:space:]]*"//;s/"[^}]*"full_name"[[:space:]]*:[[:space:]]*"/|/;s/"$//')
        
        if [ -z "$all_repos" ]; then
            all_repos="$repo_pairs"
        else
            all_repos="$all_repos"$'\n'"$repo_pairs"
        fi
        echo "   Found $count repositories on page $page" >&2
        
        if [ "$count" -lt "$per_page" ]; then
            break
        fi
        
        page=$((page + 1))
        sleep "$GITHUB_RATE_LIMIT_DELAY"
    done
    
    local total=$(echo "$all_repos" | wc -l | tr -d ' ')
    echo -e "${GREEN}✅ Total repositories found: $total${NC}" >&2
    echo "" >&2
    
    echo "$all_repos"
}

# Search for package.json and lockfiles in a repository using tree API (works without token for public repos)
search_package_json_in_repo_tree() {
    local repo_full_name="$1"
    local repo_name="$2"
    
    echo -e "   ${BLUE}Fetching repository tree...${NC}"
    
    # Get the default branch first, then pin its current commit: the tree
    # and every file then come from the same snapshot, even if the branch
    # moves while files are downloaded.
    local repo_info
    repo_info=$(github_request "https://api.github.com/repos/${repo_full_name}") || return 1
    local default_branch ref branch_info
    default_branch=$(json_get_value "$repo_info" "default_branch")
    ref="$default_branch"
    if branch_info=$(github_request "https://api.github.com/repos/${repo_full_name}/branches/${default_branch}"); then
        local commit_sha
        commit_sha=$(json_get_value "$branch_info" "sha")
        [[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] && ref="$commit_sha"
    fi

    # Get the full tree recursively
    local tree_url="https://api.github.com/repos/${repo_full_name}/git/trees/${ref}?recursive=1"
    local tree_response
    tree_response=$(github_request "$tree_url") || return 1
    if [[ "$tree_response" =~ \"truncated\"[[:space:]]*:[[:space:]]*true ]]; then
        echo "Error: GitHub returned a truncated tree for $repo_full_name" >&2
        return 1
    fi
    
    # OPTIMIZED: Use grep/sed to extract paths directly instead of slow JSON parsing
    # Extract all "path" values from the tree response and filter for target files
    # This is MUCH faster than iterating with json_array_get for large trees
    # Build the filename match regex from the ecosystem registry (+ package.json)
    local scan_regex="" _name
    for _name in $(ecosystem_scan_filenames); do
        scan_regex="${scan_regex:+$scan_regex|}${_name//./\\.}"
    done

    local target_files
    target_files=$(echo "$tree_response" | \
        grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"$//' | \
        grep -v 'node_modules' | \
        grep -E "(^|/)(${scan_regex})\$" || true)
    
    if [ -z "$target_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Count files by type
    local pkg_count=$(echo "$target_files" | grep -c "package.json" || true)
    local lock_count=$(echo "$target_files" | grep -v "package.json" | grep -c "." || true)
    echo "   Found $pkg_count package.json file(s) and $lock_count lockfile(s)"
    
    # Start from an empty repo directory, so files deleted upstream since a
    # previous fetch are not scanned again. Only a directory this tool
    # created (it holds the marker file) is cleared: a pre-existing folder of
    # the same name, such as a local workspace, is never deleted.
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    local marker=".package-checker-fetch"
    if [ -n "$repo_name" ] && [ "$repo_name" != . ] && [ "$repo_name" != .. ] && [ -f "$repo_dir/$marker" ]; then
        rm -rf -- "$repo_dir"
    fi
    mkdir -p "$repo_dir"
    printf '%s\n' "$repo_full_name" > "$repo_dir/$marker"

    # Fetch each file
    while IFS= read -r file_path; do
        [ -z "$file_path" ] && continue

        local raw_url="https://raw.githubusercontent.com/${repo_full_name}/${ref}/${file_path}"
        local file_content
        file_content=$(curl -fsSL --connect-timeout 10 --max-time 60 \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "User-Agent: package-checker-script" \
            "${raw_url// /%20}") || return 1
        
        # Save the file
        local full_path="${repo_dir}/${file_path}"
        local dir="${full_path%/*}"
        mkdir -p "$dir"
        
        printf '%s\n' "$file_content" > "$full_path" || return 1
        
        local file_name="${file_path##*/}"
        if [ "$file_name" = "package.json" ]; then
            echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
        else
            echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
        fi
    done <<< "$target_files"
}

# Create a GitHub issue with proper JSON escaping using jq
# Arguments:
#   $1 - repo_full_name (owner/repo)
#   $2 - issue_title
#   $3 - issue_body (markdown content)
#   $4 - labels (comma-separated, optional)
create_github_issue() {
    local repo_full_name="$1"
    local issue_title="$2"
    local issue_body="$3"
    local labels="${4:-security,vulnerability}"

    if [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${YELLOW}⚠️  Cannot create issue: GitHub token is required${NC}"
        return 1
    fi

    # Check if jq is available for proper JSON escaping
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}❌ jq is required for creating issues. Please install it.${NC}"
        return 1
    fi

    # Convert labels string to JSON array
    local labels_json
    labels_json=$(echo "$labels" | tr ',' '\n' | jq -R . | jq -s .)

    # Create JSON payload with proper escaping using jq
    local json_payload
    json_payload=$(jq -n \
        --arg title "$issue_title" \
        --arg body "$issue_body" \
        --argjson labels "$labels_json" \
        '{title: $title, body: $body, labels: $labels}')

    echo -e "${BLUE}📝 Creating issue on ${repo_full_name}...${NC}"

    # Make API request to create issue
    local response
    response=$(curl -sS --connect-timeout 10 --max-time 60 -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "$json_payload" \
        "https://api.github.com/repos/${repo_full_name}/issues") || return 1
    local http_code="${response##*$'\n'}"
    response="${response%$'\n'*}"

    # Check if issue was created successfully
    if [ "$http_code" = 201 ] && echo "$response" | grep -q '"html_url"'; then
        local issue_url
        issue_url=$(echo "$response" | jq -r '.html_url // empty' 2>/dev/null || echo "$response" | grep -o '"html_url":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo -e "${GREEN}✅ Issue created: ${issue_url}${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to create issue${NC}"
        if echo "$response" | grep -q '"message"'; then
            local error_msg
            error_msg=$(echo "$response" | jq -r '.message // empty' 2>/dev/null || echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            echo -e "${RED}   Error: ${error_msg}${NC}"
        fi
        return 1
    fi
}

# Fetch all packages from GitHub organization or single repo
fetch_github_packages() {
    if [ -z "$GITHUB_ORG" ] && [ -z "$GITHUB_REPO" ]; then
        echo -e "${RED}❌ Error: GitHub organization or repository is required${NC}"
        echo "   Use --github-org for an organization or --github-repo for a single repository"
        return 1
    fi
    
    # Token is required for organization scanning (repository listing)
    if [ -n "$GITHUB_ORG" ] && [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${RED}❌ Error: GitHub token is required for organization scanning${NC}"
        echo "   Set GITHUB_TOKEN environment variable or use --github-token option"
        return 1
    fi
    
    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    echo "║       Fetching Packages from GitHub                ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""
    
    if [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${YELLOW}⚠️  No GitHub token provided - using unauthenticated requests (rate limited)${NC}"
        echo ""
    fi
    
    # Create output directory
    mkdir -p "$GITHUB_OUTPUT_DIR"
    
    # Single repository mode
    if [ -n "$GITHUB_REPO" ]; then
        # Remove trailing slash if present
        local repo_full_name="${GITHUB_REPO%/}"
        local repo_name="${repo_full_name##*/}"
        
        echo -e "${BLUE}🔍 Fetching repository: $repo_full_name${NC}"
        echo ""
        echo -e "${BLUE}Processing: $repo_name${NC}"
        
        # Use tree API for single repo (works without token for public repos)
        if ! search_package_json_in_repo_tree "$repo_full_name" "$repo_name"; then
            echo -e "${RED}❌ Failed to fetch repository: $repo_full_name${NC}"
            return 1
        fi
    else
        # Organization mode - use Tree API (less rate-limited than Search API)
        local repos
        repos=$(get_github_repositories) || return 1
        
        # OPTIMIZED: repos is now newline-separated "name|full_name" pairs
        while IFS='|' read -r repo_name repo_full_name; do
            [ -z "$repo_name" ] && continue
            
            echo -e "${BLUE}Processing: $repo_name${NC}"
            
            # Use Tree API instead of Search API (much higher rate limit). An
            # empty or unreadable repository must not stop the organization scan.
            if ! search_package_json_in_repo_tree "$repo_full_name" "$repo_name"; then
                echo -e "${YELLOW}⚠️  Skipping $repo_full_name: unable to fetch its files${NC}"
            fi
            
            sleep "$GITHUB_RATE_LIMIT_DELAY"
        done <<< "$repos"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ GitHub packages fetched to: $(realpath "$GITHUB_OUTPUT_DIR")${NC}"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# ============================================================================
# GitHub issue reports (--create-multiple-issues / --create-single-issue)
#
# Findings (VULNERABLE_PACKAGES: "file|eco|name@version") are grouped by target
# repository, then by "eco:name", then by version with the files using it.
# Every advisory of a version comes from VULN_ADVISORIES (merged GHSA/OSV
# records "severity;ghsa;cve;source;fix;id"). An issue whose exact title is
# already open in the repository is not created again.
# ============================================================================
ISSUE_REPO_LIST=()
declare -A ISSUE_REPO_PKGS=()       # repo -> newline list of eco:name
declare -A ISSUE_PKG_VERSIONS=()    # repo|eco:name -> newline list of versions
declare -A ISSUE_VERSION_FILES=()   # repo|eco:name|version -> newline list of files

# Repository (owner/repo) an issue about FILE belongs to: --github-repo, or in
# organization mode the repository whose fetched copy holds the file
# ($GITHUB_OUTPUT_DIR/<repo>/...). Sets ISSUE_REPO ("" when unknown).
issue_repository_for() {
    ISSUE_REPO=""
    if [ -n "$GITHUB_REPO" ]; then
        ISSUE_REPO="${GITHUB_REPO%/}"
        return
    fi
    [ -n "$GITHUB_ORG" ] || return 0
    local file="${1#./}" dir="${GITHUB_OUTPUT_DIR%/}/"
    dir="${dir#./}"
    [[ "$file" == "$dir"*/* ]] || return 0
    file="${file#"$dir"}"
    ISSUE_REPO="$GITHUB_ORG/${file%%/*}"
}

group_findings_for_issues() {
    ISSUE_REPO_LIST=()
    ISSUE_REPO_PKGS=()
    ISSUE_PKG_VERSIONS=()
    ISSUE_VERSION_FILES=()
    local vuln file eco pv pkg ver pk vk unknown=0
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file eco pv <<< "$vuln"
        issue_repository_for "$file"
        if [ -z "$ISSUE_REPO" ]; then
            unknown=$((unknown + 1))
            continue
        fi
        pkg="$eco:${pv%@*}" ver="${pv##*@}"
        pk="$ISSUE_REPO|$pkg" vk="$ISSUE_REPO|$pkg|$ver"
        if [ -z "${ISSUE_REPO_PKGS[$ISSUE_REPO]+x}" ]; then
            ISSUE_REPO_LIST+=("$ISSUE_REPO")
            ISSUE_REPO_PKGS["$ISSUE_REPO"]=""
        fi
        if [ -z "${ISSUE_PKG_VERSIONS[$pk]+x}" ]; then
            ISSUE_REPO_PKGS["$ISSUE_REPO"]+="$pkg"$'\n'
            ISSUE_PKG_VERSIONS["$pk"]=""
        fi
        if [ -z "${ISSUE_VERSION_FILES[$vk]+x}" ]; then
            ISSUE_PKG_VERSIONS["$pk"]+="$ver"$'\n'
            ISSUE_VERSION_FILES["$vk"]="$file"
        else
            case $'\n'"${ISSUE_VERSION_FILES[$vk]}"$'\n' in
                *$'\n'"$file"$'\n'*) ;;
                *) ISSUE_VERSION_FILES["$vk"]+=$'\n'"$file" ;;
            esac
        fi
    done
    if [ "$unknown" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  ${unknown} finding(s) not attributable to a repository were left out (use --github-repo or --github-org)${NC}"
    fi
}

# Distinct advisories of one package across its versions. Sets ADV_TOTAL,
# ADV_MAX_RANK and ADV_SEV_COUNTS (index = severity rank, 0 = unknown).
package_advisory_stats() {
    local pkg="$1" versions="$2" ver advisories advisory key
    local severity ghsa cve source fix id
    local -A seen=()
    ADV_TOTAL=0 ADV_MAX_RANK=0
    ADV_SEV_COUNTS=(0 0 0 0 0)
    while IFS= read -r ver; do
        [ -n "$ver" ] || continue
        advisories="${VULN_ADVISORIES[$pkg@$ver]:-}"
        while [ -n "$advisories" ]; do
            advisory="${advisories%%||*}"
            if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
            IFS=';' read -r severity ghsa cve source fix id <<< "$advisory"
            key="${ghsa:-${cve:-${id:-$advisory}}}"
            [ -z "${seen[$key]+x}" ] || continue
            seen["$key"]=1
            severity_rank "$severity"
            ADV_SEV_COUNTS[SEV_RANK]=$(( ADV_SEV_COUNTS[SEV_RANK] + 1 ))
            ADV_TOTAL=$((ADV_TOTAL + 1))
            [ "$SEV_RANK" -le "$ADV_MAX_RANK" ] || ADV_MAX_RANK=$SEV_RANK
        done
    done <<< "$versions"
}

# Severity rank -> SEV_LABEL / SEV_EMOJI.
severity_label() {
    case "$1" in
        4) SEV_LABEL="CRITICAL" SEV_EMOJI="🔴" ;;
        3) SEV_LABEL="HIGH" SEV_EMOJI="🟠" ;;
        2) SEV_LABEL="MEDIUM" SEV_EMOJI="🟡" ;;
        1) SEV_LABEL="LOW" SEV_EMOJI="🟢" ;;
        *) SEV_LABEL="UNKNOWN" SEV_EMOJI="⚪" ;;
    esac
}

# Markdown rows of the severity summary table.
severity_summary_rows() {
    local rank rows=""
    for rank in 4 3 2 1 0; do
        [ "${ADV_SEV_COUNTS[$rank]}" -gt 0 ] || continue
        severity_label "$rank"
        rows+="| ${SEV_EMOJI} ${SEV_LABEL,,} | ${ADV_SEV_COUNTS[$rank]} |"$'\n'
    done
    printf '%s' "$rows"
}

# Markdown table of the advisories of one package version.
advisory_table() {
    local advisories="$1" advisory severity ghsa cve source fix id link
    printf '| Severity | Advisory | CVE | Source | Fixed in |\n'
    printf '|----------|----------|-----|--------|----------|\n'
    while [ -n "$advisories" ]; do
        advisory="${advisories%%||*}"
        if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
        IFS=';' read -r severity ghsa cve source fix id <<< "$advisory"
        severity_rank "$severity"
        severity_label "$SEV_RANK"
        link="-"
        if [ -n "$ghsa" ]; then link="[${ghsa}](https://github.com/advisories/${ghsa})"
        elif [ -n "$id" ]; then link="[${id}](https://osv.dev/vulnerability/${id})"
        fi
        printf '| %s %s | %s | %s | %s | %s |\n' "$SEV_EMOJI" "${severity:-unknown}" "$link" \
            "${cve:+[${cve}](https://nvd.nist.gov/vuln/detail/${cve})}" "${source:--}" "${fix:--}"
    done
}

# Titles of the open issues of a repository (one per line), so a run does not
# file the same report twice. Empty when they cannot be listed.
open_issue_titles() {
    local repo="$1" page response titles=""
    for page in 1 2 3 4 5 6 7 8 9 10; do
        response=$(github_request "https://api.github.com/repos/${repo}/issues?state=open&per_page=100&page=${page}" 2>/dev/null) || {
            echo -e "${YELLOW}⚠️  Unable to list open issues of $repo: duplicates are not checked${NC}" >&2
            break
        }
        titles+=$(printf '%s' "$response" | jq -r '.[] | select(.pull_request == null) | .title' 2>/dev/null)$'\n'
        [ "$(printf '%s' "$response" | jq 'length' 2>/dev/null)" = 100 ] || break
    done
    printf '%s' "$titles"
}

# Create an issue unless one with the same title is open (titles in $4).
create_issue_once() {
    local repo="$1" title="$2" body="$3" open_titles="$4"
    if printf '%s\n' "$open_titles" | grep -qxF -- "$title"; then
        echo -e "${BLUE}ℹ️  Already open on ${repo}: ${title}${NC}"
        return 2
    fi
    create_github_issue "$repo" "$title" "$body" "security,vulnerability,dependencies"
}

# Body of the issue about one package (eco:name) in one repository.
package_issue_body() {
    local repo="$1" pkg="$2" versions="$3"
    local eco="${pkg%%:*}" name="${pkg#*:}" ver file body
    body="## 🔒 Security Vulnerabilities in \`${name}\` (${eco})"$'\n\n'
    body+="### 📊 Summary"$'\n\n'"| Metric | Count |"$'\n'"|--------|-------|"$'\n'
    body+="| **Total Vulnerabilities** | ${ADV_TOTAL} |"$'\n'"$(severity_summary_rows)"$'\n\n'
    body+="---"$'\n\n'"### 🔍 Vulnerability Details"$'\n\n'
    while IFS= read -r ver; do
        [ -n "$ver" ] || continue
        body+="#### Version \`${ver}\`"$'\n\n'
        body+="$(advisory_table "${VULN_ADVISORIES[$pkg@$ver]:-}")"$'\n\n'
        body+="<details>"$'\n'"<summary>📁 Affected files</summary>"$'\n\n'
        while IFS= read -r file; do
            [ -n "$file" ] && body+="- \`${file}\`"$'\n'
        done <<< "${ISSUE_VERSION_FILES[$repo|$pkg|$ver]}"
        body+=$'\n'"</details>"$'\n\n'
    done <<< "$versions"
    body+="### ✅ Recommendations"$'\n\n'
    body+="1. **Update the package** to the latest patched version:"$'\n'"   \`\`\`bash"$'\n'
    body+="$(fix_commands_for_eco "$eco" "$name" "   ")"$'\n'"   \`\`\`"$'\n\n'
    body+="2. **Check for breaking changes** before updating major versions"$'\n\n'
    body+="3. **Run a security audit** after updating:"$'\n'"   \`\`\`bash"$'\n'
    body+="   $(verify_command_for_eco "$eco")"$'\n'"   \`\`\`"$'\n\n'
    body+="4. **Review the advisories** linked above for specific remediation steps"$'\n\n'
    body+="---"$'\n\n'"*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"
    printf '%s' "$body"
}

# One issue per vulnerable package, in the repository that uses it.
create_package_issues() {
    local repo pkg versions title open_titles created=0 total=0 status
    group_findings_for_issues
    for repo in "${ISSUE_REPO_LIST[@]}"; do
        open_titles=$(open_issue_titles "$repo")
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue
            total=$((total + 1))
            versions="${ISSUE_PKG_VERSIONS[$repo|$pkg]}"
            package_advisory_stats "$pkg" "$versions"
            severity_label "$ADV_MAX_RANK"
            title="${SEV_EMOJI} Security: ${ADV_TOTAL} vulnerabilit$([ "$ADV_TOTAL" -eq 1 ] && echo y || echo ies) in \`${pkg#*:}\`"
            [ "${pkg%%:*}" = npm ] || title+=" (${pkg%%:*})"
            [ "$ADV_MAX_RANK" -eq 0 ] || title+=" [${SEV_LABEL}]"
            echo -e "${BLUE}📦 ${pkg#*:}${NC} (${ADV_TOTAL} vulnerability/ies) → ${repo}"
            status=0
            create_issue_once "$repo" "$title" "$(package_issue_body "$repo" "$pkg" "$versions")" "$open_titles" || status=$?
            [ "$status" -ne 0 ] || created=$((created + 1))
            sleep 1  # Rate limiting
            echo ""
        done <<< "${ISSUE_REPO_PKGS[$repo]}"
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✅ Created ${created} issue(s) for ${total} package(s)${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# One consolidated report per repository.
create_consolidated_issues() {
    local repo pkg versions ver file title body details ecos rank status
    local total pkg_count open_titles
    local -a counts
    group_findings_for_issues
    for repo in "${ISSUE_REPO_LIST[@]}"; do
        total=0 pkg_count=0 details="" ecos=""
        counts=(0 0 0 0 0)
        local max_rank=0
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue
            pkg_count=$((pkg_count + 1))
            versions="${ISSUE_PKG_VERSIONS[$repo|$pkg]}"
            package_advisory_stats "$pkg" "$versions"
            total=$((total + ADV_TOTAL))
            for rank in 0 1 2 3 4; do counts[rank]=$(( counts[rank] + ADV_SEV_COUNTS[rank] )); done
            [ "$ADV_MAX_RANK" -le "$max_rank" ] || max_rank=$ADV_MAX_RANK
            case " $ecos " in *" ${pkg%%:*} "*) ;; *) ecos+=" ${pkg%%:*}" ;; esac
            severity_label "$ADV_MAX_RANK"
            details+="<details>"$'\n'"<summary>${SEV_EMOJI} <strong>${pkg#*:}</strong> (${pkg%%:*}, ${ADV_TOTAL} vulnerabilities)</summary>"$'\n\n'
            while IFS= read -r ver; do
                [ -n "$ver" ] || continue
                details+="**Version \`${ver}\`**"$'\n\n'"$(advisory_table "${VULN_ADVISORIES[$pkg@$ver]:-}")"$'\n\n'
                while IFS= read -r file; do
                    [ -n "$file" ] && details+="- \`${file}\`"$'\n'
                done <<< "${ISSUE_VERSION_FILES[$repo|$pkg|$ver]}"
                details+=$'\n'
            done <<< "$versions"
            details+="</details>"$'\n\n'
        done <<< "${ISSUE_REPO_PKGS[$repo]}"

        severity_label "$max_rank"
        title="${SEV_EMOJI} Security Report: ${total} vulnerabilities in ${pkg_count} packages [${SEV_LABEL}]"
        ADV_SEV_COUNTS=("${counts[@]}")
        body="## 🔒 Security Vulnerability Report"$'\n\n'
        body+="This issue contains a consolidated report of all security vulnerabilities detected in this repository."$'\n\n'
        body+="### 📊 Global Summary"$'\n\n'"| Metric | Count |"$'\n'"|--------|-------|"$'\n'
        body+="| **Total Vulnerabilities** | ${total} |"$'\n'"| **Affected Packages** | ${pkg_count} |"$'\n'
        body+="$(severity_summary_rows)"$'\n\n'"---"$'\n\n'"### 📦 Vulnerable Packages"$'\n\n'"$details"
        body+="---"$'\n\n'"### ✅ Recommended Actions"$'\n\n'
        body+="1. **Review each vulnerability** using the advisory links above."$'\n'
        body+="2. **Update the affected packages** to their latest patched versions. Commands per detected ecosystem:"$'\n\n'
        local eco
        for eco in $ecos; do
            body+="#### $(eco_display_name "$eco")"$'\n\n'"\`\`\`bash"$'\n'
            body+="$(fix_commands_for_eco "$eco" "<package-name>")"$'\n'"\`\`\`"$'\n\n'
            body+="Verify: \`$(verify_command_for_eco "$eco")\`"$'\n\n'
        done
        body+="---"$'\n\n'"*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"

        echo -e "${BLUE}Creating consolidated security report on ${repo}...${NC}"
        open_titles=$(open_issue_titles "$repo")
        status=0
        create_issue_once "$repo" "$title" "$body" "$open_titles" || status=$?
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        case "$status" in
            0) echo -e "${GREEN}✅ Created 1 consolidated issue with ${total} vulnerabilities${NC}" ;;
            2) ;;
            *) echo -e "${RED}❌ Failed to create consolidated issue${NC}" ;;
        esac
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    done
}
# CSV source parser: generates lookup-table eval statements in a single awk
# pass. Handles quoted fields, multi-line quoted values, Windows line endings
# and version ranges. Args: FILE [COLUMNS], COLUMNS being "pkg,version" as
# 1-based indexes ("1,2") or header names ("name,versions").
#
# The first line is a header when columns are given by name, or when its
# version field does not look like a version or a range; a headerless file
# therefore keeps its first row.
parse_csv_to_lookup_eval() {
    local file="$1" columns="${2:-}"
    local col1="${columns%%,*}" col2=""
    [[ "$columns" == *,* ]] && col2="${columns#*,}" && col2="${col2%%,*}"
    col1="${col1#"${col1%%[![:space:]]*}"}"; col1="${col1%"${col1##*[![:space:]]}"}"
    col2="${col2#"${col2%%[![:space:]]*}"}"; col2="${col2%"${col2##*[![:space:]]}"}"

    tr -d '\r' < "$file" | awk -v col1="$col1" -v col2="$col2" "$AWK_FEED_LIB"'
    BEGIN {
        pkg_col = 1
        ver_col = 2
        by_name = (col1 != "" && col2 != "" && !(col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/))
        if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
            pkg_col = int(col1)
            ver_col = int(col2)
        }
    }

    function meta(name) {
        return (name in meta_col) ? fields[meta_col[name]] : ""
    }

    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }

    function parse_csv_line(line, f,    i, n, in_quote, field, c) {
        n = 1
        field = ""
        in_quote = 0
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            if (c == "\"") {
                if (in_quote && substr(line, i+1, 1) == "\"") {
                    field = field "\""
                    i++
                } else {
                    in_quote = !in_quote
                }
            } else if (c == "," && !in_quote) {
                f[n] = trim(field)
                n++
                field = ""
            } else {
                field = field c
            }
        }
        f[n] = trim(field)
        return n
    }

    {
        if (pending_line != "") {
            current_line = pending_line " " $0
            pending_line = ""
        } else {
            current_line = $0
        }

        # An odd number of quotes means the quoted field continues.
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            pending_line = current_line
            next
        }

        if (current_line == "") next

        field_count = parse_csv_line(current_line, fields)

        if (!header_checked) {
            header_checked = 1
            if (by_name || (fields[ver_col] !~ /^([<>=~^*(]|[vV]?[0-9])/ && substr(fields[ver_col], 1, 1) != "[")) {
                # Header row: locate the named columns, including the
                # optional advisory metadata (severity, ghsa, cve, source).
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    if (by_name && lower_field == tolower(col1)) pkg_col = i
                    if (by_name && lower_field == tolower(col2)) ver_col = i
                    if (lower_field ~ /^(severity|ghsa|cve|source)$/) { meta_col[lower_field] = i; has_meta = 1 }
                }
                next
            }
        }

        pkg = fields[pkg_col]
        ver = fields[ver_col]
        if (pkg == "" || ver == "") next

        record = ""
        if (has_meta) {
            ranged = range_like(ver)
            record = tolower(meta("severity")) ";" meta("ghsa") ";" meta("cve") ";" meta("source") ";" (ranged ? range_fix(ver) : "") ";"
        }
        # CSV carries no ecosystem info -> wildcard namespace "*:"
        add_entry("*:" loose_name(pkg), ver, record, range_like(ver))
    }

    END { emit_lookup() }
    '
}
# Awk helpers shared by every feed parser (purl, SARIF, CycloneDX, Trivy).
# Prepended to each awk program so canonicalization cannot drift between them.
#   escape_sq(s)            quote s for a single-quoted bash eval string
#   canon_purl_name(e, n)   canonical package name for purl type e; MUST match
#                           the feed emission (src/60-feeds.sh) and the lockfile
#                           parsers (src/50-ecosystems/)
#   purl_split(p)           split "pkg:type/name@version?q" into PURL_TYPE,
#                           PURL_NAME, PURL_VERSION (both percent-decoded) and
#                           PURL_QUERY; returns 0 when p is not a versioned purl
#   loose_name(n)           key of a name in the wildcard "*:" namespace
#   add_entry / emit_lookup collect rows, then print the bash eval statements
AWK_FEED_LIB='
function escape_sq(s) {
    gsub(/'\''/, "'\''\\'\'''\''", s)
    return s
}
function canon_purl_name(eco, name,   lo, cnt, parts) {
    if (eco == "pypi") {
        # PEP 503: lowercase, collapse runs of - _ . to a single -
        lo = tolower(name)
        gsub(/[-_.]+/, "-", lo)
        return lo
    } else if (eco == "maven") {
        # groupId/artifactId -> groupId:artifactId (last two path components)
        if (index(name, ":") > 0) return name
        cnt = split(name, parts, "/")
        if (cnt >= 2) return parts[cnt-1] ":" parts[cnt]
        return name
    } else if (eco == "composer" || eco == "githubactions" || eco == "nuget") {
        return tolower(name)
    } else if (eco == "swift") {
        lo = name
        sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", lo)
        sub(/\/+$/, "", lo)
        sub(/\.git$/, "", lo)
        return tolower(lo)
    }
    # npm, golang, cargo, gem, pub, hex and unknown types: name as-is
    return name
}
function purl_split(p,   main_part, q, te, at) {
    PURL_TYPE = PURL_NAME = PURL_VERSION = PURL_QUERY = ""
    if (substr(p, 1, 4) != "pkg:") return 0
    te = index(p, "/")
    if (te <= 5) return 0
    main_part = p
    q = index(p, "?")
    # The query string may itself contain "@": split it off first.
    if (q > 0) { main_part = substr(p, 1, q - 1); PURL_QUERY = substr(p, q + 1) }
    PURL_TYPE = substr(main_part, 5, te - 5)
    # Name/version split at the LAST "@": scoped names start with "@".
    if (!match(main_part, /@[^@]*$/)) return 0
    at = RSTART
    if (at <= te + 1) return 0
    PURL_NAME = substr(main_part, te + 1, at - te - 1)
    PURL_VERSION = substr(main_part, at + 1)
    if (index(main_part, "\"")) {
        gsub(/"/, "", PURL_NAME)
        gsub(/"/, "", PURL_VERSION)
    }
    PURL_NAME = pct_decode(PURL_NAME)
    PURL_VERSION = pct_decode(PURL_VERSION)
    return PURL_NAME != "" && PURL_VERSION != ""
}
# Decode %XX escapes (%40 "@", %2F "/", %2B "+" in v1.2.3%2Bincompatible).
function pct_decode(s,   out, i, c, hex) {
    if (!index(s, "%")) return s
    out = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        hex = tolower(substr(s, i + 1, 2))
        if (c == "%" && hex ~ /^[0-9a-f][0-9a-f]$/) {
            out = out sprintf("%c", (index("0123456789abcdef", substr(hex, 1, 1)) - 1) * 16 + index("0123456789abcdef", substr(hex, 2, 1)) - 1)
            i += 2
        } else out = out c
    }
    return out
}
# Loose form of a name without ecosystem (wildcard "*:" keys of CSV, JSON and
# report sources): lowercase, runs of - _ . collapsed to "-". Must match the
# probe in check_vulnerability.
function loose_name(n) {
    n = tolower(n)
    gsub(/[-_.]+/, "-", n)
    return n
}
# Register one advisory row. key = "eco:name", version = exact version or
# range, record = "severity;ghsa;cve;source;fix;id" (id: the advisory id when
# it is neither a GHSA nor a CVE, e.g. PYSEC-, GO-, RUSTSEC-, MAL-). Ranges are newline-separated
# (they may contain "||"), exact versions "|"-separated. Every distinct record
# is kept, even when two advisories share the same range.
function add_entry(key, version, record, is_range,   meta_key, rk, vk) {
    meta_key = key (is_range ? ":" : "@") version
    rk = meta_key SUBSEP record
    # A record without any metadata adds nothing to the default one.
    if (record !~ /^;*$/ && !(rk in seen_records)) {
        seen_records[rk] = 1
        records[meta_key] = records[meta_key] record "\n"
    }
    vk = key SUBSEP version
    if (vk in seen_versions) return
    seen_versions[vk] = 1
    if (!(key in seen_keys)) { seen_keys[key] = 1; key_count++ }
    if (is_range) {
        pkg_ranges[key] = (key in pkg_ranges) ? pkg_ranges[key] "\n" version : version
    } else {
        pkg_versions[key] = (key in pkg_versions) ? pkg_versions[key] "|" version : version
    }
}
# True when a version string is a range: operators, spaces, wildcards
# (*, 1.x), OR-alternatives (| and ||) or Maven/NuGet intervals ([1.0,2.0)).
function range_like(v) {
    return (v ~ /[[:space:]<>=,^~*|]/ || index(v, "[") || index(v, "]") || v ~ /\.[xX](\.|$)/ || v ~ /^\(/)
}
# Known fixed version of a single range: its exclusive upper bound. An
# inclusive upper bound (<=) is still affected, and an OR-range (or an
# interval list) is ambiguous.
function range_fix(version) {
    if (version !~ /\||\[|\(/ && match(version, /<[0-9][^[:space:],]*/))
        return substr(version, RSTART + 1, RLENGTH - 1)
    return ""
}
# Print the counts first (FEED_PKG_COUNT: packages kept, FEED_RAW_COUNT:
# entries read before pre-filtering), then the eval statements. Appends ("+=")
# merge with tables filled by earlier sources; single quotes keep the data
# literal through eval.
function emit_lookup(   pkg, key) {
    printf "FEED_PKG_COUNT=%d\nFEED_RAW_COUNT=%d\n", key_count, (raw_count != "" ? raw_count : key_count)
    for (pkg in pkg_versions)
        printf "VULN_EXACT_LOOKUP['\''%s'\'']+='\''|%s'\''\n", escape_sq(pkg), escape_sq(pkg_versions[pkg])
    for (pkg in pkg_ranges)
        printf "VULN_RANGE_LOOKUP['\''%s'\'']+='\''%s\n'\''\n", escape_sq(pkg), escape_sq(pkg_ranges[pkg])
    for (key in records)
        printf "VULN_RECORDS['\''%s'\'']+='\''%s'\''\n", escape_sq(key), escape_sq(records[key])
}
'

# Parse a PURL feed file into lookup-table eval statements.
# Line format: pkg:type/namespace/name@version-or-range?severity=..&ghsa=..
# Example: pkg:npm/lodash@4.17.21
# Example with version range: pkg:npm/express@>=4.0.0 <4.17.0
#
# Pre-filtering: with PREFILTER_TOKENS_FILE set (see build_project_tokens), an
# entry is kept only when the last segment of its name (after the last "/" or
# ":"), lowercased with runs of - _ . collapsed to "-", is one of the project
# tokens. That segment is part of every way a package is written in a
# lockfile (npm scope/name, PEP 503 names, Maven group:artifact, Go module
# paths, Swift repository URLs, NuGet ids...), so no relevant entry is lost
# while a 300k-line feed shrinks to the few entries the project can match.
parse_purl_to_lookup_eval() {
    local file="$1"
    awk -v tokens_file="${PREFILTER_TOKENS_FILE:-}" "$AWK_FEED_LIB"'
    BEGIN {
        raw_count = 0
        filtering = (tokens_file != "")
        if (filtering) while ((getline t < tokens_file) > 0) wanted[t] = 1
    }
    function parse_query_params(query_string, params,   n, i, pairs, eq) {
        delete params
        if (query_string == "") return
        n = split(query_string, pairs, "&")
        for (i = 1; i <= n; i++) {
            eq = index(pairs[i], "=")
            if (eq > 0) params[substr(pairs[i], 1, eq - 1)] = substr(pairs[i], eq + 1)
        }
    }

    {
        # Fast path for generated feeds: one bare purl per line. Anything else
        # (indentation, CRLF, comments, blank lines) goes through a trim.
        line = $0
        last = substr(line, length(line))
        if (substr(line, 1, 4) != "pkg:" || last == "\r" || last == " " || last == "\t") {
            gsub(/^[[:space:]]+|[[:space:]\r]+$/, "", line)
            if (substr(line, 1, 4) != "pkg:") next
        }
        raw_count++
        if (filtering) {
            # Last segment of the name, without decoding the whole purl.
            q = index(line, "?")
            segment = q ? substr(line, 1, q - 1) : line
            sub(/@[^@]*$/, "", segment)
            segment = pct_decode(segment)
            sub(/\/+$/, "", segment)
            sub(/^.*[\/:]/, "", segment)
            segment = tolower(segment)
            gsub(/[-_.]+/, "-", segment)
            if (!(segment in wanted)) next
        }
        if (!purl_split(line)) next
        canon_key = PURL_TYPE ":" canon_purl_name(PURL_TYPE, PURL_NAME)
        version = PURL_VERSION
        parse_query_params(PURL_QUERY, params)

        # Ranges contain operators, spaces, wildcards or OR-alternatives.
        is_range = range_like(version)

        fix = is_range ? range_fix(version) : ""
        if ("fixed" in params) fix = params["fixed"]
        record = params["severity"] ";" params["ghsa"] ";" params["cve"] ";" params["source"] ";" fix ";" params["id"]
        add_entry(canon_key, version, record, is_range)
    }

    END { emit_lookup() }
    ' "$file"
}
# JSON-shaped source importers: SARIF, CycloneDX SBOM, Trivy JSON and the
# native JSON source format.
#
# Every importer reads json_structural_lines output (one JSON token group per
# record), so pretty-printed and minified reports parse identically, and walks
# it with the path tracker below. Each finding becomes an exact-version entry
# plus an advisory record, through the same add_entry/emit_lookup helpers as
# the purl parser (AWK_FEED_LIB in src/31-parsers-purl.sh).

# Awk JSON path tracker over json_structural_lines records. jp_step(line)
# classifies the record (JP_EVENT = open | close | scalar), keeps a stack of
# container names ("#" for an array element) and exposes JP_PATH, e.g.
# "/#/runs/#/results/#" inside a SARIF result. For a scalar, JP_KEY/JP_VAL hold
# the key and the unquoted value (escapes such as \n stay literal). On close,
# JP_PATH is the path of the container that just closed.
AWK_JSON_PATH='
function jp_step(line,   k, rest) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    JP_KEY = JP_VAL = ""
    if (line == "}" || line == "]") {
        JP_EVENT = "close"
        JP_PATH = jp_path()
        if (jp_depth > 0) jp_depth--
        return
    }
    k = "#"
    rest = line
    if (match(line, /^"([^"\\]|\\.)*"[[:space:]]*:[[:space:]]*/)) {
        k = substr(line, 1, RLENGTH)
        sub(/"[[:space:]]*:[[:space:]]*$/, "", k)
        k = substr(k, 2)
        rest = substr(line, RLENGTH + 1)
    }
    if (rest == "{" || rest == "[") {
        JP_EVENT = "open"
        jp_stack[++jp_depth] = k
        JP_PATH = jp_path()
        return
    }
    JP_EVENT = "scalar"
    JP_PATH = jp_path()
    JP_KEY = k
    if (rest ~ /^".*"$/) rest = substr(rest, 2, length(rest) - 2)
    JP_VAL = rest
}
function jp_path(   i, p) {
    p = ""
    for (i = 1; i <= jp_depth; i++) p = p "/" jp_stack[i]
    return p
}
# Advisory identifier -> ghsa/cve fields of a record.
function id_fields(id) {
    ID_GHSA = ID_CVE = ID_OTHER = ""
    if (id ~ /^GHSA-/) ID_GHSA = id
    else if (id ~ /^CVE-/) ID_CVE = id
    else ID_OTHER = id
}
# Register a finding: namespaced key from a purl when available, else the
# wildcard namespace "*:" (the report carries no ecosystem).
function add_finding(purl, name, version, severity, id, source,   key) {
    key = ""
    if (purl != "" && purl_split(purl)) {
        key = PURL_TYPE ":" canon_purl_name(PURL_TYPE, PURL_NAME)
        if (version == "") version = PURL_VERSION
    } else if (name != "") {
        key = "*:" loose_name(name)
    }
    if (key == "" || version == "") return
    id_fields(id)
    add_entry(key, version, tolower(severity) ";" ID_GHSA ";" ID_CVE ";" source ";;" ID_OTHER, 0)
}
'

# Parse a SARIF report (Trivy, Grype, ...). Each runs[].results[] entry is one
# finding. The package comes from the Trivy-style message
# ("Package: next\nInstalled Version: 16.0.3\n...") or, failing that, from a
# location message "path: name@version" (split at the LAST "@" so scoped names
# survive). ruleId carries the advisory identifier.
parse_sarif_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    function reset() { rule = level = pkg = ver = loc_pkg = loc_ver = sev = "" }
    function field(text, label,   s) {
        s = index(text, label)
        if (s == 0) return ""
        text = substr(text, s + length(label))
        sub(/\\n.*/, "", text)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", text)
        return text
    }
    BEGIN { reset() }
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/results\/#$/ && JP_KEY == "ruleId") rule = JP_VAL
            else if (JP_PATH ~ /\/results\/#$/ && JP_KEY == "level") level = JP_VAL
            else if (JP_PATH ~ /\/results\/#\/message$/ && JP_KEY == "text") {
                pkg = field(JP_VAL, "Package: ")
                ver = field(JP_VAL, "Installed Version: ")
                sev = field(JP_VAL, "Severity: ")
            } else if (JP_PATH ~ /\/locations\/#\/(physicalLocation\/)?message$/ && JP_KEY == "text" && loc_pkg == "") {
                t = JP_VAL
                sub(/^.*:[[:space:]]+/, "", t)
                at = 0
                for (i = length(t); i > 1; i--) if (substr(t, i, 1) == "@") { at = i; break }
                if (at > 1) { loc_pkg = substr(t, 1, at - 1); loc_ver = substr(t, at + 1) }
            }
        } else if (JP_EVENT == "close" && JP_PATH ~ /\/results\/#$/) {
            if (pkg == "" || ver == "") { pkg = loc_pkg; ver = loc_ver }
            if (sev == "") sev = (level == "error" ? "high" : (level == "warning" ? "medium" : ""))
            add_finding("", pkg, ver, sev, rule, "sarif")
            reset()
        }
    }
    END { emit_lookup() }
    '
}

# Parse a CycloneDX SBOM. Each vulnerabilities[] entry lists affects[].ref,
# which is either a purl or a bom-ref resolved through components[] (at any
# nesting depth). Explicit affects[].versions[] with status "affected" are
# added too. References are resolved at the end, since components may follow
# the vulnerabilities.
parse_sbom_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/components\/#$/) {
                if (JP_KEY == "bom-ref") comp_ref = JP_VAL
                else if (JP_KEY == "purl") comp_purl = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#$/ && JP_KEY == "id") {
                vid = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/ratings\/#$/ && JP_KEY == "severity" && vsev == "") {
                vsev = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#$/ && JP_KEY == "ref") {
                refs[++nrefs] = JP_VAL
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#\/versions\/#$/) {
                if (JP_KEY == "version") aver = JP_VAL
                else if (JP_KEY == "status") astatus = JP_VAL
            }
        } else if (JP_EVENT == "close") {
            if (JP_PATH ~ /\/components\/#$/) {
                if (comp_ref != "" && comp_purl != "") purl_of[comp_ref] = comp_purl
                comp_ref = comp_purl = ""
            } else if (JP_PATH ~ /\/vulnerabilities\/#\/affects\/#\/versions\/#$/) {
                if (aver != "" && (astatus == "" || astatus == "affected")) extra[nrefs] = extra[nrefs] " " aver
                aver = astatus = ""
            } else if (JP_PATH ~ /\/vulnerabilities\/#$/) {
                for (r = 1; r <= nrefs; r++) {
                    n = ++nfind
                    find_ref[n] = refs[r]; find_id[n] = vid; find_sev[n] = vsev
                    find_extra[n] = extra[r]
                }
                delete refs; delete extra
                nrefs = 0; vid = vsev = ""
            }
        }
    }
    END {
        for (n = 1; n <= nfind; n++) {
            p = find_ref[n]
            if (p !~ /^pkg:/ && (p in purl_of)) p = purl_of[p]
            if (p !~ /^pkg:/) continue
            add_finding(p, "", "", find_sev[n], find_id[n], "cyclonedx")
            cnt = split(find_extra[n], vers, " ")
            for (v = 1; v <= cnt; v++) if (vers[v] != "") add_finding(p, "", vers[v], find_sev[n], find_id[n], "cyclonedx")
        }
        emit_lookup()
    }
    '
}

# Print "eco|name|version" for every component of a CycloneDX SBOM (--sbom),
# at any nesting depth, from its purl. metadata.component is the project
# itself and metadata.tools lists the generators: neither is a dependency.
# Go purls carry a "v" prefix that go.sum parsing strips too.
cyclonedx_components() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT != "scalar" || JP_KEY != "purl" || JP_PATH !~ /\/components\/#$/ || JP_PATH ~ /^\/#\/metadata\//) next
        gsub(/\\\//, "/", JP_VAL)
        if (!purl_split(JP_VAL)) next
        if (PURL_TYPE == "golang") sub(/^v/, "", PURL_VERSION)
        print PURL_TYPE "|" canon_purl_name(PURL_TYPE, PURL_NAME) "|" PURL_VERSION
    }
    ' | sort -u
}

# Check the components of a CycloneDX SBOM given with --sbom, like a lockfile.
# A Maven build lists its transitive dependencies only there (pom.xml does not).
analyze_cyclonedx_inventory() {
    local lockfile="$1"
    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}
    local packages eco pkg_name version
    packages=$(cyclonedx_components "$lockfile")
    while IFS='|' read -r eco pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}

# Parse a Trivy JSON report (trivy fs/image --format json). Each
# Results[].Vulnerabilities[] entry is one finding; PkgIdentifier.PURL gives the
# ecosystem when present, otherwise the wildcard namespace is used.
parse_trivy_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "scalar") {
            if (JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#$/) {
                if (JP_KEY == "PkgName") pkg = JP_VAL
                else if (JP_KEY == "InstalledVersion") ver = JP_VAL
                else if (JP_KEY == "VulnerabilityID") vid = JP_VAL
                else if (JP_KEY == "Severity") sev = JP_VAL
            } else if (JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#\/PkgIdentifier$/ && JP_KEY == "PURL") {
                purl = JP_VAL
            }
        } else if (JP_EVENT == "close" && JP_PATH ~ /\/Results\/#\/Vulnerabilities\/#$/) {
            add_finding(purl, pkg, ver, sev, vid, "trivy")
            pkg = ver = vid = sev = purl = ""
        }
    }
    END { emit_lookup() }
    '
}

# Parse the JSON source format: { "<package>": { "versions": [...],
# "versions_range": [...], "severity", "ghsa", "cve", "source" } }. JSON
# sources carry no ecosystem, so entries land in the wildcard namespace "*:".
# Package objects sit at depth 2 (their names may contain "/", so depth is
# used rather than JP_PATH patterns).
parse_json_to_lookup_eval() {
    json_structural_lines "$1" | awk "$AWK_FEED_LIB$AWK_JSON_PATH"'
    {
        jp_step($0)
        if (JP_EVENT == "open" && jp_depth == 2) {
            pkg = jp_stack[2]; nv = 0; sev = ghsa = cve = src = ""
        } else if (JP_EVENT == "scalar" && jp_depth == 2 && pkg != "") {
            if (JP_KEY == "severity") sev = JP_VAL
            else if (JP_KEY == "ghsa") ghsa = JP_VAL
            else if (JP_KEY == "cve") cve = JP_VAL
            else if (JP_KEY == "source") src = JP_VAL
        } else if (JP_EVENT == "scalar" && jp_depth == 3 && pkg != "" && JP_VAL != "" &&
                   (jp_stack[3] == "versions" || jp_stack[3] == "versions_range")) {
            vals[++nv] = JP_VAL
            ranged[nv] = (jp_stack[3] == "versions_range")
        } else if (JP_EVENT == "close" && jp_depth == 1 && pkg != "") {
            # jp_depth is already popped: the package object just closed.
            for (i = 1; i <= nv; i++) {
                record = tolower(sev) ";" ghsa ";" cve ";" src ";" (ranged[i] ? range_fix(vals[i]) : "") ";"
                add_entry("*:" loose_name(pkg), vals[i], record, ranged[i])
            }
            pkg = ""
        }
    }
    END { emit_lookup() }
    '
}
detect_format_from_url() {
    local url="$1"

    # Remove query parameters and fragments first
    local clean_url="${url%%\?*}"
    clean_url="${clean_url%%\#*}"

    # Check for compound extensions first (e.g., .sarif, .sbom.cdx.json, .trivy.json)
    if [[ "$clean_url" =~ \.sarif\.json$ ]] || [[ "$clean_url" =~ \.sarif$ ]]; then
        echo "sarif"
        return
    elif [[ "$clean_url" =~ \.sbom\.cdx\.json$ ]] || [[ "$clean_url" =~ \.sbom\.json$ ]] || [[ "$clean_url" =~ \.cdx\.json$ ]]; then
        echo "sbom-cyclonedx"
        return
    elif [[ "$clean_url" =~ \.trivy\.json$ ]]; then
        echo "trivy-json"
        return
    fi

    # Fall back to simple extension detection
    local extension="${clean_url##*.}"

    case "$extension" in
        json)
            # Generic JSON format
            echo "json"
            ;;
        csv)
            echo "csv"
            ;;
        purl|txt)
            echo "purl"
            ;;
        sarif)
            echo "sarif"
            ;;
        sbom)
            echo "sbom-cyclonedx"
            ;;
        trivy)
            echo "trivy-json"
            ;;
        cdx)
            echo "sbom-cyclonedx"
            ;;
        *)
            # Default to json if unknown
            echo "json"
            ;;
    esac
}

# Load data source
load_data_source() {
    local url="$1"
    local format="${2:-}"
    local name="${3:-$url}"
    local csv_columns="${4:-}"

    # Auto-detect format if not provided
    if [ -z "$format" ]; then
        format=$(detect_format_from_url "$url")
        echo -e "${BLUE}🔍 Loading: $name (auto-detected format: $format)${NC}"
    else
        echo -e "${BLUE}🔍 Loading: $name${NC}"
    fi

    echo "   URL: $url"
    echo "   Format: $format"

    local parser
    case "$format" in
        json) parser=parse_json_to_lookup_eval ;;
        csv) parser=parse_csv_to_lookup_eval ;;
        purl) parser=parse_purl_to_lookup_eval ;;
        sarif) parser=parse_sarif_to_lookup_eval ;;
        sbom|sbom-cyclonedx) parser=parse_sbom_to_lookup_eval ;;
        trivy|trivy-json) parser=parse_trivy_to_lookup_eval ;;
        *)
            echo -e "${RED}❌ Error: Unsupported format '$format'${NC}"
            return 1
            ;;
    esac

    # Parsers read a local file: download remote sources to a temp file first.
    local file="$url" downloaded=""
    if [[ "$url" =~ ^(https?|ftp):// ]]; then
        if ! downloaded=$(mktemp); then
            echo -e "${RED}❌ Error: Unable to create a temporary file${NC}"
            return 1
        fi
        register_temp_file "$downloaded"
        if ! curl -fsSL --connect-timeout 10 --max-time 120 -o "$downloaded" "$url"; then
            rm -f -- "$downloaded"
            echo -e "${RED}❌ Error: Unable to download from $url${NC}"
            return 1
        fi
        file="$downloaded"
    elif [ ! -f "$url" ]; then
        echo -e "${RED}❌ Error: Local file not found: $url${NC}"
        return 1
    fi

    local status=0 eval_commands=""
    case "$format" in
        json|sarif|sbom|sbom-cyclonedx|trivy|trivy-json)
            if ! json_is_valid_file "$file"; then
                echo "Error: Invalid JSON in $name"
                status=1
            fi
            ;;
    esac
    if [ "$status" = 0 ]; then
        [ -z "$csv_columns" ] || echo "   CSV Columns: $csv_columns"
        if ! eval_commands=$("$parser" "$file" "$csv_columns"); then
            echo -e "${RED}❌ Error: Unable to parse $name${NC}"
            status=1
        fi
    fi
    [ -z "$downloaded" ] || rm -f -- "$downloaded"
    [ "$status" = 0 ] || return 1

    # Sets FEED_PKG_COUNT / FEED_RAW_COUNT, then fills the lookup tables,
    # merging with every source loaded before.
    FEED_PKG_COUNT=0 FEED_RAW_COUNT=0
    eval "$eval_commands"

    LAST_SOURCE_ENTRY_COUNT="$FEED_RAW_COUNT"
    TOTAL_SOURCE_ENTRIES=$(( ${TOTAL_SOURCE_ENTRIES:-0} + FEED_RAW_COUNT ))
    if [ "$format" = purl ] && [ -n "${PREFILTER_TOKENS_FILE:-}" ]; then
        echo -e "${GREEN}✅ Loaded ${FEED_PKG_COUNT} packages from $name (${FEED_RAW_COUNT} entries before pre-filtering)${NC}"
    else
        echo -e "${GREEN}✅ Loaded ${FEED_PKG_COUNT} packages from $name${NC}"
    fi
    echo ""
    LOADED_SOURCE_COUNT=$((LOADED_SOURCE_COUNT + 1))

    return 0
}

# Load configuration file
load_config_file() {
    local config_path="$1"
    local load_sources="${2:-true}"

    if [ ! -f "$config_path" ]; then
        return 1
    fi
    
    echo -e "${BLUE}📋 Loading configuration from: $config_path${NC}"
    echo ""
    
    # Read config file content (a UTF-8 BOM is not part of the JSON)
    local config_content
    config_content=$(cat "$config_path")
    config_content="${config_content#$'\xef\xbb\xbf'}"
    if ! json_is_valid "$config_content"; then
        echo "Error: Invalid JSON in configuration: $config_path"
        return 1
    fi
    
    # Parse github settings if present
    local github_obj=$(json_get_object "$config_content" "github")
    if [ -n "$github_obj" ] && [ "$github_obj" != "{}" ]; then
        local cfg_github_org=$(json_get_value "$github_obj" "org")
        local cfg_github_repo=$(json_get_value "$github_obj" "repo")
        local cfg_github_token=$(json_get_value "$github_obj" "token")
        local cfg_github_output=$(json_get_value "$github_obj" "output")
        
        # Apply github settings if not already set via command line
        if [ -z "$GITHUB_ORG" ] && [ -n "$cfg_github_org" ] && [ "$cfg_github_org" != "null" ] && [ "$cfg_github_org" != "" ]; then
            GITHUB_ORG="$cfg_github_org"
        fi
        if [ -z "$GITHUB_REPO" ] && [ -n "$cfg_github_repo" ] && [ "$cfg_github_repo" != "null" ] && [ "$cfg_github_repo" != "" ]; then
            GITHUB_REPO="$cfg_github_repo"
        fi
        if [ -z "$GITHUB_TOKEN" ] && [ -n "$cfg_github_token" ] && [ "$cfg_github_token" != "null" ] && [ "$cfg_github_token" != "" ]; then
            GITHUB_TOKEN="$cfg_github_token"
        fi
        if [ -n "$cfg_github_output" ] && [ "$cfg_github_output" != "null" ] && [ "$cfg_github_output" != "" ]; then
            # Only override if it's still the default value
            if [ "$GITHUB_OUTPUT_DIR" = "./packages" ]; then
                GITHUB_OUTPUT_DIR="$cfg_github_output"
            fi
        fi
    fi
    
    # Parse options settings if present
    local options_obj=$(json_get_object "$config_content" "options")
    if [ -n "$options_obj" ] && [ "$options_obj" != "{}" ]; then
        # Parse ignore_paths array
        local ignore_paths_array=$(json_get_array "$options_obj" "ignore_paths")
        if [ "$ignore_paths_array" != "[]" ] && [ -n "$ignore_paths_array" ]; then
            CONFIG_IGNORE_PATHS=()
            local ignore_count=$(json_array_length "$ignore_paths_array")
            for i in $(seq 0 $((ignore_count - 1))); do
                local path_val=$(json_array_get "$ignore_paths_array" $i)
                path_val=$(echo "$path_val" | sed 's/^"//;s/"$//')
                CONFIG_IGNORE_PATHS+=("$path_val")
            done
        fi
        
        # Parse dependency_types array
        local dep_types_array=$(json_get_array "$options_obj" "dependency_types")
        if [ "$dep_types_array" != "[]" ] && [ -n "$dep_types_array" ]; then
            CONFIG_DEPENDENCY_TYPES=()
            local dep_count=$(json_array_length "$dep_types_array")
            for i in $(seq 0 $((dep_count - 1))); do
                local dep_val=$(json_array_get "$dep_types_array" $i)
                dep_val=$(echo "$dep_val" | sed 's/^"//;s/"$//')
                CONFIG_DEPENDENCY_TYPES+=("$dep_val")
            done
        fi

        # Parse ecosystems array (default-feed loading override; the CLI
        # --ecosystems flag takes precedence over this when both are set).
        local ecosystems_array=$(json_get_array "$options_obj" "ecosystems")
        if [ "$ecosystems_array" != "[]" ] && [ -n "$ecosystems_array" ]; then
            CONFIG_ECOSYSTEMS=""
            local eco_count=$(json_array_length "$ecosystems_array")
            for i in $(seq 0 $((eco_count - 1))); do
                local eco_val=$(json_array_get "$ecosystems_array" $i)
                eco_val=$(echo "$eco_val" | sed 's/^"//;s/"$//')
                CONFIG_ECOSYSTEMS="${CONFIG_ECOSYSTEMS:+$CONFIG_ECOSYSTEMS }$eco_val"
            done
        fi

        # Runtime version check (Node.js, PHP): on unless "runtime_check": false
        local runtime_check_val=$(json_get_value "$options_obj" "runtime_check")
        [ "$runtime_check_val" != false ] || CONFIG_RUNTIME_CHECK=false
    fi
    
    # Parse config file and extract sources array
    local sources_array=$(json_get_array "$config_content" "sources")
    local sources_count=$(json_array_length "$sources_array")
    
    if [ "$load_sources" != true ]; then
        [ "$sources_count" -eq 0 ] || echo -e "${BLUE}ℹ️  Configuration sources ignored: sources given on the command line take precedence${NC}"
    elif [ "$sources_count" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Warning: No sources found in configuration file${NC}"
        # Don't return 1 here - config may still have github settings
    else
        for i in $(seq 0 $((sources_count - 1))); do
            local source_obj=$(json_array_get "$sources_array" $i)
            
            # Try to get url from "source" or "url" field
            local url=$(json_get_value "$source_obj" "source")
            if [ -z "$url" ] || [ "$url" = "null" ]; then
                url=$(json_get_value "$source_obj" "url")
            fi
            
            local format=$(json_get_value "$source_obj" "format")
            local name=$(json_get_value "$source_obj" "name")
            local columns=$(json_get_value "$source_obj" "columns")
            
            # Set default name if not provided
            if [ -z "$name" ] || [ "$name" = "null" ]; then
                name="Source $((i+1))"
            fi
            
            # Handle null/empty values
            [ "$format" = "null" ] && format=""
            [ "$columns" = "null" ] && columns=""
            
            # Pass format only if explicitly specified
            if [ -n "$format" ]; then
                load_data_source "$url" "$format" "$name" "$columns" || return 1
            else
                load_data_source "$url" "" "$name" "$columns" || return 1
            fi
        done
    fi
    
    return 0
}
get_base_version() {
    local version="$1"
    # Extract major.minor.patch, removing any pre-release or build metadata
    # Use parameter expansion to avoid subshell (much faster)
    local base="${version%%-*}"  # Remove everything after first dash
    base="${base%%+*}"           # Also remove build metadata after +
    echo "$base"
}

# Compare two semver versions
# Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
# OPTIMIZED: Sets COMPARE_RESULT global instead of echo (avoids subshell when called)
compare_versions() {
    # Build metadata never changes version precedence.
    local v1="$1"
    local v2="$2"
    v1="${v1%%+*}"
    v2="${v2%%+*}"
    # Tags such as v1.2.3 (cargo git deps, actions, swift) carry a cosmetic 'v'.
    [[ "$v1" == [vV][0-9]* ]] && v1="${v1:1}"
    [[ "$v2" == [vV][0-9]* ]] && v2="${v2:1}"

    # Split base (x.y.z[.w...]) from the pre-release tail (first '-' onward).
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare every numeric base part (missing parts count as 0) ---
    local -a parts1 parts2
    IFS='.' read -ra parts1 <<< "$base1"
    IFS='.' read -ra parts2 <<< "$base2"
    local i n1 n2 nparts=${#parts1[@]}
    [ "${#parts2[@]}" -gt "$nparts" ] && nparts=${#parts2[@]}
    [ "$nparts" -lt 3 ] && nparts=3
    for (( i = 0; i < nparts; i++ )); do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        # Decimal identifiers have no size limit in SemVer. Comparing lengths
        # then ASCII digits avoids shell integer overflow.
        while [[ "$n1" == 0* && ${#n1} -gt 1 ]]; do n1="${n1#0}"; done
        while [[ "$n2" == 0* && ${#n2} -gt 1 ]]; do n2="${n2#0}"; done
        if (( ${#n1} < ${#n2} )); then COMPARE_RESULT="-1"; return; fi
        if (( ${#n1} > ${#n2} )); then COMPARE_RESULT="1"; return; fi
        if [[ "$n1" < "$n2" ]]; then COMPARE_RESULT="-1"; return; fi
        if [[ "$n1" > "$n2" ]]; then COMPARE_RESULT="1"; return; fi
    done

    # --- Pre-release comparison (base versions are equal) ---
    local pre1="" pre2=""
    [ "$v1" != "$base1" ] && pre1="${v1#*-}"
    [ "$v2" != "$base2" ] && pre2="${v2#*-}"

    # A version with a pre-release has LOWER precedence than one without.
    if [ -z "$pre1" ] && [ -z "$pre2" ]; then COMPARE_RESULT="0"; return; fi
    if [ -z "$pre1" ]; then COMPARE_RESULT="1"; return; fi
    if [ -z "$pre2" ]; then COMPARE_RESULT="-1"; return; fi

    # Both have pre-release: compare dot-split identifiers left to right.
    local ids1 ids2
    IFS='.' read -ra ids1 <<< "$pre1"
    IFS='.' read -ra ids2 <<< "$pre2"
    local len1=${#ids1[@]}
    local len2=${#ids2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2

    local j id1 id2 isnum1 isnum2
    for (( j = 0; j < maxlen; j++ )); do
        # A larger set of pre-release fields (prefix-superset) wins.
        if [ "$j" -ge "$len1" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$j" -ge "$len2" ]; then COMPARE_RESULT="1"; return; fi

        id1="${ids1[$j]}"
        id2="${ids2[$j]}"
        [ "$id1" = "$id2" ] && continue

        # Numeric identifiers rank below alphanumeric ones; two numerics
        # compare numerically; two alphanumerics compare lexically (ASCII).
        case "$id1" in ''|*[!0-9]*) isnum1=0 ;; *) isnum1=1 ;; esac
        case "$id2" in ''|*[!0-9]*) isnum2=0 ;; *) isnum2=1 ;; esac

        if [ "$isnum1" = 1 ] && [ "$isnum2" = 1 ]; then
            while [[ "$id1" == 0* && ${#id1} -gt 1 ]]; do id1="${id1#0}"; done
            while [[ "$id2" == 0* && ${#id2} -gt 1 ]]; do id2="${id2#0}"; done
            if (( ${#id1} < ${#id2} )); then COMPARE_RESULT="-1"; return; fi
            if (( ${#id1} > ${#id2} )); then COMPARE_RESULT="1"; return; fi
            if [[ "$id1" < "$id2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$id1" > "$id2" ]]; then COMPARE_RESULT="1"; return; fi
        elif [ "$isnum1" = 1 ]; then
            COMPARE_RESULT="-1"; return
        elif [ "$isnum2" = 1 ]; then
            COMPARE_RESULT="1"; return
        else
            if [[ "$id1" < "$id2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$id1" > "$id2" ]]; then COMPARE_RESULT="1"; return; fi
        fi
    done

    COMPARE_RESULT="0"
}

# Convert one semver shorthand token (~ and ^, full or partial) into its
# comparator pair. Sets EXPANDED_RANGE (no subshell: called per distinct range).
# ~1.2.3 -> >=1.2.3 <1.3.0     ~1.2 -> >=1.2.0 <1.3.0     ~1 -> >=1.0.0 <2.0.0
# ^1.2.3 -> >=1.2.3 <2.0.0     ^0.2 -> >=0.2.0 <0.3.0     ^1 -> >=1.0.0 <2.0.0
# Anything else is returned unchanged.
expand_semver_range() {
    local range="$1"
    EXPANDED_RANGE="$range"
    [[ "$range" =~ ^([~^])([0-9]+)(\.([0-9]+))?(\.([0-9]+))?(.*)$ ]] || return 0
    local op="${BASH_REMATCH[1]}" major="${BASH_REMATCH[2]}"
    local minor="${BASH_REMATCH[4]}" patch="${BASH_REMATCH[6]}" tail="${BASH_REMATCH[7]}"
    # A partial version cannot carry a pre-release tail (~1.2-beta is not semver).
    if [ -n "$tail" ] && [ -z "$patch" ]; then return 0; fi
    local lower="$major.${minor:-0}.${patch:-0}$tail"

    if [ "$op" = "~" ]; then
        if [ -z "$minor" ]; then
            EXPANDED_RANGE=">=$lower <$((major + 1)).0.0"
        else
            EXPANDED_RANGE=">=$lower <$major.$((minor + 1)).0"
        fi
    elif [ "$major" != 0 ] || [ -z "$minor" ]; then
        EXPANDED_RANGE=">=$lower <$((major + 1)).0.0"
    elif [ "$minor" != 0 ] || [ -z "$patch" ]; then
        EXPANDED_RANGE=">=$lower <0.$((minor + 1)).0"
    else
        EXPANDED_RANGE=">=$lower <0.0.$((patch + 1))"
    fi
}

# Pessimistic constraint (Ruby ~>, PEP 440 ~=, Composer ~): the last given
# part may grow. ~>2.2 -> >=2.2 <3   ~>2.2.3 -> >=2.2.3 <2.3   ~>2 -> >=2 <3
# Sets EXPANDED_RANGE ("!" when the version has no numeric part).
expand_pessimistic_range() {
    local ver="$1"
    [[ "$ver" =~ ^[vV]?([0-9]+(\.[0-9]+)*) ]] || { EXPANDED_RANGE="!"; return 0; }
    local -a parts
    IFS='.' read -ra parts <<< "${BASH_REMATCH[1]}"
    local last=$(( ${#parts[@]} - 1 ))
    [ "$last" -eq 0 ] || { unset 'parts[last]'; last=$((last - 1)); }
    parts[last]=$(( 10#${parts[last]} + 1 ))
    local IFS='.'
    EXPANDED_RANGE=">=$ver <${parts[*]}"
}

# X-range token: an operator and a version ending in a wildcard (1.x, 1.2.*,
# ==1.*, >=2.x). $1 operator ("" = "=" = "=="), $2 the numeric prefix (1, 1.2).
# 1.x -> >=1 <2   1.2.* -> >=1.2 <1.3   >1.x -> >=2   <=1.x -> <2
# Sets EXPANDED_RANGE ("!" when it cannot be expressed as one AND list).
expand_x_range() {
    local op="$1" base="$2" next
    local -a parts
    IFS='.' read -ra parts <<< "$base"
    local last=$(( ${#parts[@]} - 1 ))
    parts[last]=$(( 10#${parts[last]} + 1 ))
    next="${parts[*]}"
    next="${next// /.}"
    case "$op" in
        ""|=|==) EXPANDED_RANGE=">=$base <$next" ;;
        ">=") EXPANDED_RANGE=">=$base" ;;
        ">") EXPANDED_RANGE=">=$next" ;;
        "<") EXPANDED_RANGE="<$base" ;;
        "<=") EXPANDED_RANGE="<$next" ;;
        *) EXPANDED_RANGE="!" ;;
    esac
}

# Maven / NuGet interval notation -> comparator alternatives. Sets
# INTERVAL_RANGE (unchanged input when it is not an interval list).
# [1.0,2.0) -> >=1.0 <2.0   (,1.0] -> <=1.0   [1.0] -> =1.0   [1.0,) -> >=1.0
# [1.0,1.5),[2.0,2.5) -> >=1.0 <1.5 || >=2.0 <2.5
_prepare_interval() {
    local rest="$1" out="" alt low high
    local re='^[[:space:]]*([[(])([^],()]*)(,([^],()]*))?([])])[[:space:]]*(,(.*))?$'
    INTERVAL_RANGE="$1"
    while [ -n "$rest" ]; do
        [[ "$rest" =~ $re ]] || return 0
        low="${BASH_REMATCH[2]// /}" high="${BASH_REMATCH[4]// /}"
        if [ -z "${BASH_REMATCH[3]}" ]; then
            [ -n "$low" ] || return 0
            alt="=$low"
        else
            alt=""
            if [ -n "$low" ]; then
                if [ "${BASH_REMATCH[1]}" = "[" ]; then alt=">=$low"; else alt=">$low"; fi
            fi
            if [ -n "$high" ]; then
                if [ "${BASH_REMATCH[5]}" = "]" ]; then alt+="${alt:+ }<=$high"; else alt+="${alt:+ }<$high"; fi
            fi
            [ -n "$alt" ] || alt="*"
        fi
        out+="${out:+ || }$alt"
        rest="${BASH_REMATCH[7]}"
    done
    INTERVAL_RANGE="$out"
}

# Parsed form of every distinct range string seen so far: "op ver op ver ..."
# ("*" matches everything, "!" never matches), keyed "eco|range" since an
# operator may depend on the ecosystem (Composer ~1.2 is >=1.2 <2.0). Ranges
# repeat across thousands of lockfile entries, so normalization runs once per
# distinct string.
declare -A RANGE_CACHE=()
declare -A INTERVAL_CACHE=()

# Normalize one range (no "|" alternatives) into RANGE_CACHE[$2]. Custom
# sources write ranges in many dialects: ">=1.0,<2.0", ">= 1.0", "==1.0",
# "=1.0", "^1", "~1.2", "~>2.2", "~=2.2", "!=1.5", "1.x", "1.2.*",
# "1.2.3 - 2.3.4".
_prepare_range() {
    local raw="$1" key="$2" r="$1" token op ver parsed="" bad=""
    r="${r//,/ }"
    # Hyphen range: "1.2.3 - 2.3.4" -> >=1.2.3 <=2.3.4; a partial upper bound
    # admits its whole line ("1.2 - 2" -> >=1.2 <3).
    if [[ "$r" =~ ^[[:space:]]*[vV]?([0-9][^[:space:]]*)[[:space:]]+-[[:space:]]+[vV]?([0-9][^[:space:]]*)[[:space:]]*$ ]]; then
        local lower="${BASH_REMATCH[1]}" upper="${BASH_REMATCH[2]}"
        if [[ "$upper" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            expand_x_range "<=" "$upper"
            r=">=$lower $EXPANDED_RANGE"
        else
            r=">=$lower <=$upper"
        fi
    fi
    # Glue a detached operator to its version: ">= 1.0" -> ">=1.0".
    while [[ "$r" =~ ^(.*)(\>=|\<=|==|!=|~\>|~=|\>|\<|=|\^|~)[[:space:]]+(.*)$ ]]; do
        r="${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
    done
    local -a tokens
    read -ra tokens <<< "$r"
    local expanded=""
    for token in "${tokens[@]}"; do
        case "$token" in
            # A lone wildcard admits everything: it adds no constraint.
            "*"|x|X) continue ;;
        esac
        if [[ "$token" =~ ^(\>=|\<=|==|!=|\>|\<|=|\^|~)?[vV]?([0-9]+(\.[0-9]+)*)\.[xX*](\.[xX*])*$ ]]; then
            op="${BASH_REMATCH[1]}" ver="${BASH_REMATCH[2]}"
            case "$op" in
                "^"|"~") expand_semver_range "$op$ver" ;;
                *) expand_x_range "$op" "$ver" ;;
            esac
            expanded+="$EXPANDED_RANGE "
            continue
        fi
        case "$token" in
            "~>"*|"~="*) expand_pessimistic_range "${token:2}"; expanded+="$EXPANDED_RANGE " ;;
            "~"*)
                if [ "${key%%|*}" = composer ]; then
                    expand_pessimistic_range "${token:1}"
                else
                    expand_semver_range "$token"
                fi
                expanded+="$EXPANDED_RANGE " ;;
            "^"*) expand_semver_range "$token"; expanded+="$EXPANDED_RANGE " ;;
            *) expanded+="$token " ;;
        esac
    done
    if [ -z "$expanded" ]; then
        RANGE_CACHE["$key"]="*"
        return
    fi
    read -ra tokens <<< "$expanded"
    for token in "${tokens[@]}"; do
        if [[ "$token" =~ ^(\>=|\<=|==|!=|\>|\<|=)(.+)$ ]]; then
            op="${BASH_REMATCH[1]}" ver="${BASH_REMATCH[2]}"
            [ "$op" = "==" ] && op="="
        elif [[ "$token" =~ ^[vV]?[0-9] ]]; then
            op="=" ver="$token"     # a bare version is an exact constraint
        else
            bad="$token"; break
        fi
        parsed+="$op $ver "
    done
    if [ -n "$bad" ] || [ -z "$parsed" ]; then
        RANGE_CACHE["$key"]="!"
        [ -n "$raw" ] && echo -e "${YELLOW}⚠️  Warning: unsupported version range '$raw' (token '$bad'); it never matches${NC}" >&2
        return
    fi
    RANGE_CACHE["$key"]="${parsed% }"
}

# Check if a version is within a range
# Range format: ">1.0.0 <=2.0.0" or ">=1.0.0 <2.0.0" etc.
# Pre-release versions are included if their base version is within the range
version_in_range() {
    local version="$1"
    local range="$2"

    # Maven / NuGet intervals become "||" alternatives first: their commas
    # separate bounds, not AND-ed constraints.
    local interval_re='^[[:space:]]*[[(]'
    if [[ "$range" =~ $interval_re ]]; then
        [ -n "${INTERVAL_CACHE[$range]+x}" ] || { _prepare_interval "$range"; INTERVAL_CACHE["$range"]="$INTERVAL_RANGE"; }
        range="${INTERVAL_CACHE[$range]}"
    fi

    # Split alternatives ("||", and Composer's single "|") before expanding
    # shorthand; otherwise the upper bound generated for the first caret
    # branch is attached to the last branch.
    if [[ "$range" == *"|"* ]]; then
        local rest="${range#*|}"
        version_in_range "$version" "${range%%|*}" && return 0
        version_in_range "$version" "${rest#|}"
        return $?
    fi
    range="${range#"${range%%[![:space:]]*}"}"
    range="${range%"${range##*[![:space:]]}"}"

    # Guard against empty range (should not match any version)
    if [ -z "$range" ]; then
        return 1
    fi
    [ "$range" = "*" ] && return 0
    local cache_key="${CHECK_ECO:-npm}|$range"
    [ -n "${RANGE_CACHE[$cache_key]+x}" ] || _prepare_range "$range" "$cache_key"
    local parsed="${RANGE_CACHE[$cache_key]}"
    [ "$parsed" = "*" ] && return 0
    [ "$parsed" = "!" ] && return 1

    # Get base version for pre-release handling
    local base_version="${version%%-*}"
    base_version="${base_version%%+*}"
    local is_prerelease=false
    if [ "$version" != "$base_version" ]; then
        is_prerelease=true
    fi

    local -a conditions
    read -ra conditions <<< "$parsed"
    local idx operator range_version

    for (( idx = 0; idx < ${#conditions[@]}; idx += 2 )); do
        operator="${conditions[$idx]}"
        range_version="${conditions[$((idx + 1))]}"

        # ">=0" admits every version, including pre-releases of 0.0.0 such as
        # Go pseudo-versions (0.0.0-2021...) and npm 0.0.0-experimental builds.
        if [ "$operator" = ">=" ] && [[ "$range_version" =~ ^[vV]?0(\.0)*$ ]]; then
            continue
        fi
        # Identical strings compare equal under every ecosystem comparator.
        if [ "$version" = "$range_version" ]; then
            COMPARE_RESULT=0
        # For pre-release versions, use base version for comparison
        # This allows 19.0.0-rc.1 to be considered as within >=19.0.0
        # OPTIMIZED: dispatch on CHECK_ECO and use COMPARE_RESULT (avoids subshell).
        # npm/everything-else routes to the shared semver comparator; only
        # ecosystems with their own comparator (e.g. golang) diverge.
        elif [ "$is_prerelease" = true ] && [ "${CHECK_ECO:-npm}" = npm ]; then
            # Special handling for >= operator with pre-release
            # 19.0.0-rc is considered >= 19.0.0 (it's a pre-release OF 19.0.0)
            if [ "$operator" = ">=" ] && [ "$base_version" = "$range_version" ]; then
                COMPARE_RESULT="0"  # Consider it equal for >= comparison
            else
                compare_versions_eco "${CHECK_ECO:-npm}" "$version" "$range_version"
            fi
        else
            compare_versions_eco "${CHECK_ECO:-npm}" "$version" "$range_version"
        fi

        case "$operator" in
            "=")
                [ "$COMPARE_RESULT" = "0" ] || return 1
                ;;
            "!=")
                [ "$COMPARE_RESULT" != "0" ] || return 1
                ;;
            ">")
                if [ "$COMPARE_RESULT" != "1" ]; then
                    return 1  # version is not > range_version
                fi
                ;;
            ">=")
                if [ "$COMPARE_RESULT" = "-1" ]; then
                    return 1  # version is < range_version
                fi
                ;;
            "<")
                if [ "$COMPARE_RESULT" != "-1" ]; then
                    return 1  # version is not < range_version
                fi
                ;;
            "<=")
                if [ "$COMPARE_RESULT" = "1" ]; then
                    return 1  # version is > range_version
                fi
                ;;
        esac
    done
    return 0
}

# Check if a version matches a vulnerable version (exact or pre-release of it)
version_matches_vulnerable() {
    local installed_version="$1"
    local versions="$2"
    
    # Exact match
    if [ "$installed_version" = "$versions" ]; then
        return 0
    fi

    # Other ecosystems use their own version equality. npm retains the
    # historical conservative prerelease-of-exact matching policy below.
    if [ "${CHECK_ECO:-npm}" != npm ]; then
        compare_versions_eco "$CHECK_ECO" "$installed_version" "$versions"
        [ "$COMPARE_RESULT" = 0 ]
        return $?
    fi
    
    # Check if installed version is a pre-release of the vulnerable version
    # For example: "19.0.0-rc-xxx" should match "19.0.0"
    local installed_base="${installed_version%%-*}"
    installed_base="${installed_base%%+*}"
    
    if [ "$installed_base" = "$versions" ] && [ "$installed_version" != "$installed_base" ]; then
        # It's a pre-release version (has suffix) and base matches
        return 0
    fi
    
    return 1
}
# Comparator dispatch — routes a candidate/range version comparison to the
# ecosystem-appropriate comparator. Matching code passes CHECK_ECO (set by
# check_vulnerability); everything that is not a special-cased ecosystem falls
# through to the shared semver compare_versions (runtime included: Node.js and
# PHP versions are plain x.y.z).
#
# Contract mirrors compare_versions: sets the global COMPARE_RESULT (-1/0/1),
# no stdout, no subshell.
compare_versions_eco() {
    case "$1" in
        golang) compare_versions_go "$2" "$3" ;;
        pypi)   compare_versions_pep440 "$2" "$3" ;;
        gem)    compare_versions_gem "$2" "$3" ;;
        maven)  compare_versions_maven "$2" "$3" ;;
        nuget)  compare_versions_nuget "$2" "$3" ;;
        composer) compare_versions_composer "$2" "$3" ;;
        pub)    compare_versions_pub "$2" "$3" ;;
        *)      compare_versions "$2" "$3" ;;
    esac
}
# PEP 440 version comparator (Python / PyPI ordering).
#
# Routed to from compare_versions_eco when CHECK_ECO=pypi. A wrong ordering in a
# security tool silently produces false negatives, so this follows the reference
# `packaging` sort-key algorithm (epoch, release, pre, post, dev, local) exactly:
#
#   version := [N!]release[{a|b|rc}N][.postN][.devN][+local]
#
#   * epoch   (N!)     compares first, numerically (default 0).
#   * release (x.y.z)  numeric, dot-split, zero-padded (1.0 == 1.0.0,
#                      1.0.10 > 1.0.2).
#   * ordering within a release:
#         dev  <  pre(a<b<rc)  <  final  <  post
#     Precisely, mirroring packaging's _cmpkey:
#       - a version with ONLY a .devN (no pre, no post) ranks BELOW every
#         pre-release of that release   (1.0.dev1 < 1.0a1);
#       - a version with no pre-release ranks ABOVE all pre-releases
#         (1.0rc1 < 1.0), and a post-release ranks above the final
#         (1.0 < 1.0.post1);
#       - a trailing .devN drops a version just below its non-dev sibling
#         (1.0rc1.dev1 < 1.0rc1, 1.0.post1.dev1 < 1.0.post1);
#       - pre/post/dev NUMBERS compare numerically.
#   * local (+...) is IGNORED for ordering/range matching (1.0+local == 1.0).
#
# Normalization before comparing (case-insensitive):
#   alpha->a  beta->b  c|pre|preview->rc ; post|rev|r and a bare -N suffix
#   -> .postN ; optional . / - / _ separators between parts (1.0-a1 == 1.0a1) ;
#   a leading `v` is stripped (V1.0 == 1.0) ; implicit numbers default to 0
#   (1.0a == 1.0a0).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.

# Parse one normalized PEP 440 version into the _PEP_* globals:
#   _PEP_EPOCH                       epoch integer
#   _PEP_REL                         array of release segments (integers)
#   _PEP_PRERANK  _PEP_PRELET  _PEP_PRENUM
#         PRERANK: 0 = dev-only (below pre-releases), 1 = has pre-release,
#                  2 = no pre-release (final/post). PRELET: a=0 b=1 rc=2.
#   _PEP_POSTRANK _PEP_POSTNUM       POSTRANK 0 = no post, 1 = has post.
#   _PEP_DEVRANK  _PEP_DEVNUM        DEVRANK  0 = has dev,  1 = no dev.
_pep440_parse() {
    local v="$1"

    # Trim surrounding whitespace, lowercase, strip a leading `v`, drop local.
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v,,}"
    v="${v#v}"
    v="${v%%+*}"

    # Epoch: leading "N!".
    local epoch=0
    case "$v" in
        *'!'*) epoch="${v%%!*}"; v="${v#*!}" ;;
    esac
    _PEP_EPOCH="$epoch"

    # One regex splits release / pre / post / dev. Group map:
    #   1 release   4 pre-letter   5 pre-num
    #   6 post-any  7 implicit -N post   10 explicit post-num
    #   11 dev-any  13 dev-num
    local re='^([0-9]+(\.[0-9]+)*)([-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?((-[0-9]+)|([-_.]?(post|rev|r)[-_.]?([0-9]+)?))?([-_.]?(dev)[-_.]?([0-9]+)?)?$'

    if [[ "$v" =~ $re ]]; then
        # Release segments.
        local rel="${BASH_REMATCH[1]}"
        local IFS='.'
        # SC2206: intentional word-split of the dotted release on IFS='.' into
        # the release-segment array (values are digits only — no globbing risk).
        # shellcheck disable=SC2206
        _PEP_REL=($rel)
        unset IFS

        # Pre-release.
        local prelet="${BASH_REMATCH[4]}"
        if [ -n "$prelet" ]; then
            _PEP_PRENUM="${BASH_REMATCH[5]:-0}"
            case "$prelet" in
                a|alpha)          _PEP_PRELET=0 ;;
                b|beta)           _PEP_PRELET=1 ;;
                c|rc|pre|preview) _PEP_PRELET=2 ;;
                *)                _PEP_PRELET=0 ;;
            esac
        else
            _PEP_PRENUM=0
            _PEP_PRELET=0
        fi

        # Post-release (implicit "-N" or explicit post/rev/r[N]).
        local has_post=0 postnum=0
        if [ -n "${BASH_REMATCH[6]}" ]; then
            has_post=1
            if [ -n "${BASH_REMATCH[7]}" ]; then
                postnum="${BASH_REMATCH[7]#-}"
            else
                postnum="${BASH_REMATCH[10]:-0}"
            fi
        fi
        _PEP_POSTRANK="$has_post"
        _PEP_POSTNUM="$postnum"

        # Dev-release.
        local has_dev=0 devnum=0
        if [ -n "${BASH_REMATCH[11]}" ]; then
            has_dev=1
            devnum="${BASH_REMATCH[13]:-0}"
        fi
        _PEP_DEVNUM="$devnum"
        # DEVRANK: present sorts first (0), absent sorts last (1 == +inf).
        if [ "$has_dev" = 1 ]; then _PEP_DEVRANK=0; else _PEP_DEVRANK=1; fi

        # PRERANK: dev-only (no pre, no post, has dev) sinks below pre-releases.
        if [ -n "$prelet" ]; then
            _PEP_PRERANK=1
        elif [ "$has_post" = 0 ] && [ "$has_dev" = 1 ]; then
            _PEP_PRERANK=0
        else
            _PEP_PRERANK=2
        fi
    else
        # Unparseable tail: treat the whole thing as a bare release so ordering
        # stays deterministic rather than crashing the scan.
        local IFS='.'
        # SC2206: intentional word-split of the leading numeric-dotted run on
        # IFS='.' into the release-segment array (digits only — no globbing risk).
        # shellcheck disable=SC2206
        _PEP_REL=(${v%%[!0-9.]*})
        unset IFS
        [ "${#_PEP_REL[@]}" -eq 0 ] && _PEP_REL=(0)
        _PEP_PRERANK=2; _PEP_PRELET=0; _PEP_PRENUM=0
        _PEP_POSTRANK=0; _PEP_POSTNUM=0
        _PEP_DEVRANK=1;  _PEP_DEVNUM=0
    fi
}

compare_versions_pep440() {
    _pep440_parse "$1"
    local e1="$_PEP_EPOCH"
    local rel1=("${_PEP_REL[@]}")
    local prerank1="$_PEP_PRERANK" prelet1="$_PEP_PRELET" prenum1="$_PEP_PRENUM"
    local postrank1="$_PEP_POSTRANK" postnum1="$_PEP_POSTNUM"
    local devrank1="$_PEP_DEVRANK" devnum1="$_PEP_DEVNUM"

    _pep440_parse "$2"
    local e2="$_PEP_EPOCH"
    local rel2=("${_PEP_REL[@]}")
    local prerank2="$_PEP_PRERANK" prelet2="$_PEP_PRELET" prenum2="$_PEP_PRENUM"
    local postrank2="$_PEP_POSTRANK" postnum2="$_PEP_POSTNUM"
    local devrank2="$_PEP_DEVRANK" devnum2="$_PEP_DEVNUM"

    # 1. Epoch (numeric; 10# guards any leading zeros).
    if (( 10#$e1 < 10#$e2 )); then COMPARE_RESULT="-1"; return; fi
    if (( 10#$e1 > 10#$e2 )); then COMPARE_RESULT="1";  return; fi

    # 2. Release, segment by segment, zero-padded (missing segment == 0).
    local len1=${#rel1[@]} len2=${#rel2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2
    local i s1 s2
    for (( i = 0; i < maxlen; i++ )); do
        s1="${rel1[$i]:-0}"; s2="${rel2[$i]:-0}"
        if (( 10#$s1 < 10#$s2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$s1 > 10#$s2 )); then COMPARE_RESULT="1";  return; fi
    done

    # 3. Pre-release group (dev-only < pre < final/post).
    if [ "$prerank1" -lt "$prerank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$prerank1" -gt "$prerank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$prerank1" = 1 ]; then
        if [ "$prelet1" -lt "$prelet2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$prelet1" -gt "$prelet2" ]; then COMPARE_RESULT="1";  return; fi
        if (( 10#$prenum1 < 10#$prenum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$prenum1 > 10#$prenum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    # 4. Post-release (no post < post; then post number).
    if [ "$postrank1" -lt "$postrank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$postrank1" -gt "$postrank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$postrank1" = 1 ]; then
        if (( 10#$postnum1 < 10#$postnum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$postnum1 > 10#$postnum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    # 5. Dev-release (has dev < no dev; then dev number).
    if [ "$devrank1" -lt "$devrank2" ]; then COMPARE_RESULT="-1"; return; fi
    if [ "$devrank1" -gt "$devrank2" ]; then COMPARE_RESULT="1";  return; fi
    if [ "$devrank1" = 0 ]; then
        if (( 10#$devnum1 < 10#$devnum2 )); then COMPARE_RESULT="-1"; return; fi
        if (( 10#$devnum1 > 10#$devnum2 )); then COMPARE_RESULT="1";  return; fi
    fi

    COMPARE_RESULT="0"
}
# Go module versions use the shared semver comparator after removing the
# module-specific leading v. Pseudo-versions follow prerelease ordering.
compare_versions_go() {
    compare_versions "${1#v}" "${2#v}"
}
# RubyGems version comparator (Gem::Version ordering). Routed to from
# compare_versions_eco when CHECK_ECO=gem.
#
# RubyGems ordering, verified segment-by-segment against real `Gem::Version`
# (ruby -rrubygems):
#   * a literal `-` is canonicalized to `.pre.` BEFORE splitting, so
#     `1.0-1` and `1.0.pre.1` parse to identical segments (and compare equal);
#   * the (dash-canonicalized) string is tokenized into segments by BOTH the
#     literal dots AND every digit/letter boundary — `2a1` -> `2`, `a`, `1`
#     (same as the explicit `2.a.1`), `1.0.b1` -> `1`, `0`, `b`, `1`;
#   * segments are compared left to right; a missing trailing segment on the
#     shorter side defaults to `0` (`1.0 == 1.0.0`);
#   * two numeric segments compare numerically (`1.0.10 > 1.0.2`);
#   * two string segments compare lexically (ASCII, `1.0.a < 1.0.b`);
#   * a string segment ALWAYS ranks below a numeric segment at the same
#     position — including a numeric segment that only exists because the
#     other side ran out (padded to `0`) — which is exactly what makes any
#     version with a trailing string segment a prerelease of its release
#     (`1.0.0.pre.1 < 1.0.0`, `3.0.0.beta1 < 3.0.0`).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path (tokenizing is a pure bash regex/slice loop,
# same style as the go/pep440 comparators' identifier loops).

# Tokenize a (dash-canonicalized) version string into the global array
# _GEM_SEGS: every maximal digit-run or letter-run becomes one segment; dots
# and any other stray character are pure separators and are dropped.
_gem_tokenize() {
    local s="$1"
    _GEM_SEGS=()
    local tok
    while [ -n "$s" ]; do
        if [[ "$s" =~ ^[0-9]+ ]]; then
            tok="${BASH_REMATCH[0]}"
            _GEM_SEGS+=("$tok")
            s="${s:${#tok}}"
        elif [[ "$s" =~ ^[A-Za-z]+ ]]; then
            tok="${BASH_REMATCH[0]}"
            _GEM_SEGS+=("$tok")
            s="${s:${#tok}}"
        else
            # '.' separator (or any other stray char, e.g. a leftover '+'):
            # skip exactly one character and keep scanning.
            s="${s:1}"
        fi
    done
}

# Gem::Version#canonical_segments: drop trailing zeros from the release part
# (numeric segments before the first string) and from the prerelease part, so
# 1.0.0.pre.1 == 1.0.pre.1 and 1.0.0 == 1.
_gem_canonical() {
    local -a release=() pre=()
    local seg in_pre=0
    for seg in "${_GEM_SEGS[@]}"; do
        if [ "$in_pre" = 0 ] && [[ "$seg" == *[!0-9]* ]]; then in_pre=1; fi
        if [ "$in_pre" = 1 ]; then pre+=("$seg"); else release+=("$seg"); fi
    done
    while [ "${#release[@]}" -gt 0 ] && [[ "${release[-1]}" =~ ^0+$ ]]; do unset "release[$(( ${#release[@]} - 1 ))]"; done
    while [ "${#pre[@]}" -gt 0 ] && [[ "${pre[-1]}" =~ ^0+$ ]]; do unset "pre[$(( ${#pre[@]} - 1 ))]"; done
    _GEM_SEGS=("${release[@]}" "${pre[@]}")
}

compare_versions_gem() {
    # Canonicalize: '-' introduces a prerelease, identically to '.pre.'.
    local v1="${1//-/.pre.}"
    local v2="${2//-/.pre.}"

    _gem_tokenize "$v1"
    _gem_canonical
    local -a segs1=("${_GEM_SEGS[@]}")
    _gem_tokenize "$v2"
    _gem_canonical
    local -a segs2=("${_GEM_SEGS[@]}")

    local len1=${#segs1[@]} len2=${#segs2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2

    local i s1 s2 isnum1 isnum2
    for (( i = 0; i < maxlen; i++ )); do
        s1="${segs1[$i]:-0}"
        s2="${segs2[$i]:-0}"
        [ "$s1" = "$s2" ] && continue

        case "$s1" in ''|*[!0-9]*) isnum1=0 ;; *) isnum1=1 ;; esac
        case "$s2" in ''|*[!0-9]*) isnum2=0 ;; *) isnum2=1 ;; esac

        if [ "$isnum1" = 1 ] && [ "$isnum2" = 1 ]; then
            # 10# guards against octal misinterpretation of leading zeros.
            if [ "$((10#$s1))" -lt "$((10#$s2))" ]; then COMPARE_RESULT="-1"; return; fi
            if [ "$((10#$s1))" -gt "$((10#$s2))" ]; then COMPARE_RESULT="1"; return; fi
        elif [ "$isnum1" = 0 ] && [ "$isnum2" = 1 ]; then
            COMPARE_RESULT="-1"; return   # string segment < numeric segment
        elif [ "$isnum1" = 1 ] && [ "$isnum2" = 0 ]; then
            COMPARE_RESULT="1"; return    # numeric segment > string segment
        else
            if [[ "$s1" < "$s2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$s1" > "$s2" ]]; then COMPARE_RESULT="1"; return; fi
        fi
    done

    COMPARE_RESULT="0"
}
# Maven version comparator (Apache Maven ComparableVersion ordering). Routed to
# from compare_versions_eco when CHECK_ECO=maven.
#
# This is a faithful port of org.apache.maven.artifact.versioning.ComparableVersion
# (verified against apache/maven maven-3.9.x). A wrong ordering in a security tool
# silently produces false negatives, so the algorithm is reproduced exactly rather
# than approximated:
#
# PARSING (parseVersion): the lowercased string is tokenized into a tree of Items
# (INT / STRING / nested LIST). Separators are '.' and '-', AND every digit<->letter
# transition also splits a token. A '-' (and each digit/letter transition) opens a
# new nested sub-list, so "1.0alpha1" and "1.0-alpha-1" parse to the identical tree
# [1, [alpha, [1]]]. An empty token at a separator inserts an integer 0.
#
# QUALIFIER RANKING (comparableQualifier): known qualifiers map to their index in
#   alpha(0) < beta(1) < milestone(2) < rc(3) < snapshot(4) < ""(5, release) < sp(6)
# and unknown qualifiers map to the string "7-<qualifier>". Qualifiers are compared
# as STRINGS (byte order), so an unknown qualifier ("7-xyz") sorts lexically AFTER
# sp and the release ("5"/"6") — e.g. 1.0-xyz > 1.0. Aliases (case-insensitive):
# ga/final/release -> "" ; cr -> rc ; and a single letter a/b/m -> alpha/beta/
# milestone but ONLY when immediately followed by a digit (a1 == alpha-1, while a
# trailing bare "a" stays the unknown qualifier "a").
#
# ITEM COMPARISON:
#   * INT vs INT      : numeric (arbitrary precision — length then byte compare).
#   * INT vs STRING   : INT wins (1.1 > 1-sp, so a numeric item outranks a qualifier).
#   * INT vs LIST     : INT wins.
#   * STRING vs STRING: comparableQualifier byte compare.
#   * STRING vs LIST  : STRING loses (-1).
#   * LIST vs LIST    : element-wise; a shorter list pads with a "null" item and the
#                       missing side's compare is inverted (x.compareTo(null)).
#   * X vs null       : INT 0 == null; STRING vs null == comparableQualifier vs "5"
#                       (release); LIST vs null == firstChild vs null (empty == null).
#
# NORMALIZATION trims trailing "null" items (integer 0, release/empty qualifier,
# empty list) from each list, so 1.0 == 1.0.0 == 1-0 == 1.0-0. This is why a
# trailing 0 (1.0) equals a missing segment (1) yet 2.0.1 > 2.0.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout, no
# subshell in the hot path (the tree is built in flat bash arrays and walked with
# plain recursion — no command substitution, no external processes).

# Allocate one tree node. $1=type (0=int,1=string,2=list) $2=value. The node id
# is returned in _MV_RET; per-comparison state lives in dynamically-scoped locals
# declared by compare_versions_maven (_MV_TYPE / _MV_VAL / _MV_KIDS / _MV_N).
_mv_new() {
    _MV_TYPE[$_MV_N]="$1"
    _MV_VAL[$_MV_N]="$2"
    _MV_KIDS[$_MV_N]=""
    _MV_RET=$_MV_N
    _MV_N=$((_MV_N + 1))
}

# Append child node $2 to list node $1.
_mv_addkid() {
    if [ -z "${_MV_KIDS[$1]}" ]; then
        _MV_KIDS[$1]="$2"
    else
        _MV_KIDS[$1]="${_MV_KIDS[$1]} $2"
    fi
}

# Build a StringItem node from a raw (already-lowercased) qualifier token.
# $2=followedByDigit (1/0) enables the single-letter a/b/m aliases; ga/final/
# release/cr aliases always apply. Result id in _MV_RET.
_mv_new_string() {
    local val="$1"
    if [ "$2" = 1 ] && [ "${#val}" -eq 1 ]; then
        case "$val" in
            a) val="alpha" ;;
            b) val="beta" ;;
            m) val="milestone" ;;
        esac
    fi
    case "$val" in
        ga|final|release) val="" ;;
        cr) val="rc" ;;
    esac
    _mv_new 1 "$val"
}

# parseItem: a digit token becomes an INT node (leading zeros stripped, but at
# least one digit kept); anything else becomes a StringItem (followedByDigit=0).
_mv_parseitem() {
    if [ "$1" = 1 ]; then
        local v="$2"
        while [ "${#v}" -gt 1 ] && [ "${v:0:1}" = "0" ]; do v="${v:1}"; done
        _mv_new 0 "$v"
    else
        _mv_new_string "$2" 0
    fi
}

# comparableQualifier -> _MV_CQ. Known qualifiers map to their single-digit index;
# unknown qualifiers map to "7-<qualifier>" (so they byte-sort above sp/release).
_mv_cq() {
    case "$1" in
        alpha)     _MV_CQ="0" ;;
        beta)      _MV_CQ="1" ;;
        milestone) _MV_CQ="2" ;;
        rc)        _MV_CQ="3" ;;
        snapshot)  _MV_CQ="4" ;;
        "")        _MV_CQ="5" ;;
        sp)        _MV_CQ="6" ;;
        *)         _MV_CQ="7-$1" ;;
    esac
}

# Byte-order string compare -> _MV_CMP (LC_ALL=C is set by the entrypoint so this
# is a true code-point comparison, matching Java String.compareTo for this charset).
_mv_strcmp() {
    if [[ "$1" < "$2" ]]; then _MV_CMP=-1
    elif [[ "$1" > "$2" ]]; then _MV_CMP=1
    else _MV_CMP=0
    fi
}

# Arbitrary-precision numeric compare of two leading-zero-stripped digit strings
# -> _MV_CMP (shorter string is the smaller number; equal length falls back to
# byte compare, which equals numeric order for equal-length digit strings).
_mv_numcmp() {
    if [ "${#1}" -lt "${#2}" ]; then _MV_CMP=-1; return; fi
    if [ "${#1}" -gt "${#2}" ]; then _MV_CMP=1; return; fi
    _mv_strcmp "$1" "$2"
}

# isNull: integer 0, release/empty qualifier, or empty list. Returns 0 (true) when
# the node contributes nothing (subject to trailing trimming in normalize).
_mv_isnull() {
    case "${_MV_TYPE[$1]}" in
        0) [ "${_MV_VAL[$1]}" = "0" ] ;;
        1) [ -z "${_MV_VAL[$1]}" ] ;;
        2) [ -z "${_MV_KIDS[$1]}" ] ;;
    esac
}

# ListItem.normalize: drop trailing null items, continuing past non-null nested
# lists (matching Maven's `else if (!(lastItem instanceof ListItem)) break`).
_mv_normalize() {
    local -a kids=(${_MV_KIDS[$1]})
    local i cid
    for (( i = ${#kids[@]} - 1; i >= 0; i-- )); do
        cid="${kids[$i]}"
        if _mv_isnull "$cid"; then
            unset 'kids[$i]'
        elif [ "${_MV_TYPE[$cid]}" != 2 ]; then
            break
        fi
    done
    _MV_KIDS[$1]="${kids[*]}"
}

# parseVersion: tokenize $1 into a normalized Item tree; root list id -> _MV_RET.
_mv_parse() {
    local version="${1,,}"
    _mv_new 2 ""
    local root=$_MV_RET
    local -a stack=("$root")
    local list=$root
    local isDigit=0 startIndex=0
    local n=${#version} i c
    for (( i = 0; i < n; i++ )); do
        c="${version:i:1}"
        if [ "$c" = "." ]; then
            if [ "$i" -eq "$startIndex" ]; then
                _mv_new 0 "0"; _mv_addkid "$list" "$_MV_RET"
            else
                _mv_parseitem "$isDigit" "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
            fi
            startIndex=$((i + 1))
        elif [ "$c" = "-" ]; then
            if [ "$i" -eq "$startIndex" ]; then
                _mv_new 0 "0"; _mv_addkid "$list" "$_MV_RET"
            else
                _mv_parseitem "$isDigit" "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
            fi
            startIndex=$((i + 1))
            _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
        elif [[ "$c" == [0-9] ]]; then
            if [ "$isDigit" = 0 ] && [ "$i" -gt "$startIndex" ]; then
                if [ -n "${_MV_KIDS[$list]}" ]; then
                    _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
                fi
                _mv_new_string "${version:startIndex:i-startIndex}" 1; _mv_addkid "$list" "$_MV_RET"
                startIndex=$i
                _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
            fi
            isDigit=1
        else
            if [ "$isDigit" = 1 ] && [ "$i" -gt "$startIndex" ]; then
                _mv_parseitem 1 "${version:startIndex:i-startIndex}"; _mv_addkid "$list" "$_MV_RET"
                startIndex=$i
                _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
            fi
            isDigit=0
        fi
    done
    if [ "$n" -gt "$startIndex" ]; then
        if [ "$isDigit" = 0 ] && [ -n "${_MV_KIDS[$list]}" ]; then
            _mv_new 2 ""; _mv_addkid "$list" "$_MV_RET"; list=$_MV_RET; stack+=("$list")
        fi
        _mv_parseitem "$isDigit" "${version:startIndex}"; _mv_addkid "$list" "$_MV_RET"
    fi
    # Normalize deepest-first (Maven pops the creation stack LIFO).
    for (( i = ${#stack[@]} - 1; i >= 0; i-- )); do
        _mv_normalize "${stack[$i]}"
    done
    _MV_RET=$root
}

# Compare item $1 (always concrete) against item $2 (a node id, or "" for null).
# Result -> _MV_CMP (-1/0/1). Recurses for nested lists.
_mv_compare() {
    local l="$1" r="$2"
    local lt="${_MV_TYPE[$l]}"
    if [ -z "$r" ]; then
        case "$lt" in
            0) if [ "${_MV_VAL[$l]}" = "0" ]; then _MV_CMP=0; else _MV_CMP=1; fi ;;
            1) _mv_cq "${_MV_VAL[$l]}"; _mv_strcmp "$_MV_CQ" "5" ;;
            2) if [ -z "${_MV_KIDS[$l]}" ]; then
                   _MV_CMP=0
               else
                   local -a lk=(${_MV_KIDS[$l]}); _mv_compare "${lk[0]}" ""
               fi ;;
        esac
        return
    fi
    local rt="${_MV_TYPE[$r]}"
    case "$lt" in
        0) case "$rt" in
               0) _mv_numcmp "${_MV_VAL[$l]}" "${_MV_VAL[$r]}" ;;
               *) _MV_CMP=1 ;;
           esac ;;
        1) case "$rt" in
               0) _MV_CMP=-1 ;;
               1) _mv_cq "${_MV_VAL[$l]}"; local cl="$_MV_CQ"; _mv_cq "${_MV_VAL[$r]}"; _mv_strcmp "$cl" "$_MV_CQ" ;;
               2) _MV_CMP=-1 ;;
           esac ;;
        2) case "$rt" in
               0) _MV_CMP=-1 ;;
               1) _MV_CMP=1 ;;
               2) _mv_listcmp "$l" "$r" ;;
           esac ;;
    esac
}

# ListItem vs ListItem: walk children in lock-step, padding the shorter side with
# a null item and inverting that side's comparison (Maven's -1 * r.compareTo(l)).
_mv_listcmp() {
    local -a lk=(${_MV_KIDS[$1]}) rk=(${_MV_KIDS[$2]})
    local nl=${#lk[@]} nr=${#rk[@]}
    local max=$nl
    [ "$nr" -gt "$max" ] && max=$nr
    local i lc rc
    for (( i = 0; i < max; i++ )); do
        if [ "$i" -lt "$nl" ]; then lc="${lk[$i]}"; else lc=""; fi
        if [ "$i" -lt "$nr" ]; then rc="${rk[$i]}"; else rc=""; fi
        if [ -z "$lc" ]; then
            _mv_compare "$rc" ""
            _MV_CMP=$(( -1 * _MV_CMP ))
        else
            _mv_compare "$lc" "$rc"
        fi
        [ "$_MV_CMP" -ne 0 ] && return
    done
    _MV_CMP=0
}

compare_versions_maven() {
    # Byte-order collation for all qualifier/string compares (C locale == Java's
    # code-point order for the ASCII charset Maven versions use); standard IFS for
    # the array split/join the tree walk relies on. Both are function-local.
    local LC_ALL=C IFS=$' \t\n'
    local -a _MV_TYPE=() _MV_VAL=() _MV_KIDS=()
    local _MV_N=0 _MV_RET="" _MV_CMP=0 _MV_CQ=""

    _mv_parse "$1"; local r1=$_MV_RET
    _mv_parse "$2"; local r2=$_MV_RET
    _mv_compare "$r1" "$r2"
    COMPARE_RESULT="$_MV_CMP"
}
# NuGet version comparator (NuGet.Versioning ordering). Routed to from
# compare_versions_eco when CHECK_ECO=nuget.
#
# NuGet versions are SemVer 2.0.0 PLUS an optional 4th numeric Revision
# component: Major.Minor.Patch[.Revision][-prerelease][+metadata]. This is a
# separate comparator because compare_versions only knows Major.Minor.Patch — it has no
# concept of a 4th part, so it cannot be reused as-is:
#   - build metadata (+meta) is stripped before comparison (SemVer 2.0.0:
#     MUST be ignored for precedence), same as the go comparator strips
#     +incompatible/+meta;
#   - the Major.Minor.Patch.Revision QUAD is compared here directly, numeric
#     part by numeric part; a missing Revision defaults to 0 (1.0.0 ==
#     1.0.0.0), same rule the base compare_versions applies to a missing
#     Patch;
#   - once the quad is equal, the pre-release tail is compared using full
#     SemVer-2 rules: dot-split identifiers, numeric identifiers compare
#     numerically and rank below alphanumeric ones, and a longer identifier
#     list that is a prefix-superset of the shorter one wins — the exact same
#     dot-split ordering as the shared semver comparator, adapted to the
#     case-insensitive rule below;
#   - NuGet pre-release labels are compared CASE-INSENSITIVELY (this is where
#     NuGet actually diverges from strict SemVer 2.0.0, which is
#     case-sensitive): "1.0.0-BETA" == "1.0.0-beta". Both pre-release tails
#     are lowercased before the dot-split comparison; the numeric quad itself
#     has no case to normalize.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.
compare_versions_nuget() {
    # Strip build metadata (+meta) — ignored for precedence per SemVer 2.0.0.
    local v1="${1%%+*}"
    local v2="${2%%+*}"

    # Split base (Major.Minor.Patch[.Revision]) from the pre-release tail.
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare the Major.Minor.Patch.Revision quad numerically ---
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)
    unset IFS
    local i n1 n2
    for i in 0 1 2 3; do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        if [ "$n1" -lt "$n2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$n1" -gt "$n2" ]; then COMPARE_RESULT="1"; return; fi
    done

    # --- Pre-release comparison (quads are equal) ---
    local pre1="" pre2=""
    [ "$v1" != "$base1" ] && pre1="${v1#*-}"
    [ "$v2" != "$base2" ] && pre2="${v2#*-}"

    # A version with a pre-release has LOWER precedence than one without.
    if [ -z "$pre1" ] && [ -z "$pre2" ]; then COMPARE_RESULT="0"; return; fi
    if [ -z "$pre1" ]; then COMPARE_RESULT="1"; return; fi
    if [ -z "$pre2" ]; then COMPARE_RESULT="-1"; return; fi

    # NuGet pre-release labels are case-insensitive: normalize before compare.
    pre1="${pre1,,}"
    pre2="${pre2,,}"

    # Both have a pre-release: compare dot-split identifiers left to right
    # (identical shape to compare_versions_go's pre-release loop).
    local ids1 ids2
    IFS='.' read -ra ids1 <<< "$pre1"
    IFS='.' read -ra ids2 <<< "$pre2"
    local len1=${#ids1[@]}
    local len2=${#ids2[@]}
    local maxlen=$len1
    [ "$len2" -gt "$maxlen" ] && maxlen=$len2

    local j id1 id2 isnum1 isnum2
    for (( j = 0; j < maxlen; j++ )); do
        # A larger set of pre-release fields (prefix-superset) wins.
        if [ "$j" -ge "$len1" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$j" -ge "$len2" ]; then COMPARE_RESULT="1"; return; fi

        id1="${ids1[$j]}"
        id2="${ids2[$j]}"
        [ "$id1" = "$id2" ] && continue

        # Numeric identifiers rank below alphanumeric ones; two numerics
        # compare numerically; two alphanumerics compare lexically (ASCII).
        case "$id1" in ''|*[!0-9]*) isnum1=0 ;; *) isnum1=1 ;; esac
        case "$id2" in ''|*[!0-9]*) isnum2=0 ;; *) isnum2=1 ;; esac

        if [ "$isnum1" = 1 ] && [ "$isnum2" = 1 ]; then
            if [ "$id1" -lt "$id2" ]; then COMPARE_RESULT="-1"; return; fi
            if [ "$id1" -gt "$id2" ]; then COMPARE_RESULT="1"; return; fi
        elif [ "$isnum1" = 1 ]; then
            COMPARE_RESULT="-1"; return
        elif [ "$isnum2" = 1 ]; then
            COMPARE_RESULT="1"; return
        else
            if [[ "$id1" < "$id2" ]]; then COMPARE_RESULT="-1"; return; fi
            if [[ "$id1" > "$id2" ]]; then COMPARE_RESULT="1"; return; fi
        fi
    done

    COMPARE_RESULT="0"
}
# Composer (Packagist) version comparator. Routed to from compare_versions_eco
# when CHECK_ECO=composer.
#
# Composer's VersionParser normalizes before comparing, and its ordering is not
# semver's:
#   * a leading "v" is cosmetic (v2.4.0 == 2.4.0);
#   * the numeric part has any number of components (1.2.3.4), missing ones
#     count as 0;
#   * the stability suffix may be glued to the number (9.4.0RC1 == 9.4.0-RC1)
#     and orders dev < alpha (a) < beta (b) < RC < stable < patch (pl, p);
#   * "-pN" is a post-release patch (Magento 2.4.7-p4 > 2.4.7), not a
#     pre-release;
#   * the stability number compares numerically (beta10 > beta9).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell.

# Split a composer version into the globals _CV_NUMS (array of numeric parts),
# _CV_RANK (stability rank), _CV_NUM (stability number) and _CV_TAIL (anything
# left, compared lexically).
_composer_parse() {
    local v="${1,,}"
    v="${v%%+*}"
    [[ "$v" == v[0-9]* ]] && v="${v:1}"
    local nums="" rest=""
    if [[ "$v" =~ ^([0-9]+(\.[0-9]+)*)(.*)$ ]]; then
        nums="${BASH_REMATCH[1]}"
        rest="${BASH_REMATCH[3]}"
    else
        rest="$v"
    fi
    IFS='.' read -ra _CV_NUMS <<< "$nums"
    _CV_RANK=4 _CV_NUM=0 _CV_TAIL=""
    rest="${rest#[-._]}"
    [ -z "$rest" ] && return
    if [[ "$rest" =~ ^(dev|alpha|beta|rc|patch|pl|stable|a|b|c|p)[-._]?([0-9]*)(.*)$ ]]; then
        case "${BASH_REMATCH[1]}" in
            dev) _CV_RANK=0 ;;
            alpha|a) _CV_RANK=1 ;;
            beta|b) _CV_RANK=2 ;;
            rc|c) _CV_RANK=3 ;;
            stable) _CV_RANK=4 ;;
            patch|pl|p) _CV_RANK=5 ;;
        esac
        _CV_NUM="${BASH_REMATCH[2]:-0}"
        _CV_TAIL="${BASH_REMATCH[3]}"
    else
        # Unknown suffix: rank it like a pre-release so it stays inside "<x.y.z".
        _CV_RANK=0
        _CV_TAIL="$rest"
    fi
}

compare_versions_composer() {
    _composer_parse "$1"
    local -a nums1=("${_CV_NUMS[@]}")
    local rank1=$_CV_RANK num1=$_CV_NUM tail1=$_CV_TAIL
    _composer_parse "$2"
    local -a nums2=("${_CV_NUMS[@]}")
    local rank2=$_CV_RANK num2=$_CV_NUM tail2=$_CV_TAIL

    local i n1 n2 len=${#nums1[@]}
    [ "${#nums2[@]}" -gt "$len" ] && len=${#nums2[@]}
    for (( i = 0; i < len; i++ )); do
        n1="${nums1[$i]:-0}" n2="${nums2[$i]:-0}"
        while [[ "$n1" == 0* && ${#n1} -gt 1 ]]; do n1="${n1#0}"; done
        while [[ "$n2" == 0* && ${#n2} -gt 1 ]]; do n2="${n2#0}"; done
        if (( ${#n1} != ${#n2} )); then
            (( ${#n1} < ${#n2} )) && COMPARE_RESULT=-1 || COMPARE_RESULT=1
            return
        fi
        if [[ "$n1" < "$n2" ]]; then COMPARE_RESULT=-1; return; fi
        if [[ "$n1" > "$n2" ]]; then COMPARE_RESULT=1; return; fi
    done

    if (( rank1 != rank2 )); then
        (( rank1 < rank2 )) && COMPARE_RESULT=-1 || COMPARE_RESULT=1
        return
    fi
    if (( 10#$num1 != 10#$num2 )); then
        (( 10#$num1 < 10#$num2 )) && COMPARE_RESULT=-1 || COMPARE_RESULT=1
        return
    fi
    if [[ "$tail1" < "$tail2" ]]; then COMPARE_RESULT=-1; return; fi
    if [[ "$tail1" > "$tail2" ]]; then COMPARE_RESULT=1; return; fi
    COMPARE_RESULT=0
}
# Pub (Dart) version comparator. Routed to from compare_versions_eco when
# CHECK_ECO=pub.
#
# Pub orders build metadata, unlike semver: 0.3.5 < 0.3.5+1 < 0.3.5+2 (pub
# publishes fixes as "+N" builds). Versions compare as semver first; when they
# are equal, a version without build metadata is lower, and two builds compare
# like pre-release identifiers (dot-separated, numeric parts numerically).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell.
compare_versions_pub() {
    local v1="$1" v2="$2" build1="" build2=""
    [[ "$v1" == *+* ]] && build1="${v1#*+}"
    [[ "$v2" == *+* ]] && build2="${v2#*+}"
    compare_versions "${v1%%+*}" "${v2%%+*}"
    [ "$COMPARE_RESULT" = 0 ] || return 0
    if [ -z "$build1" ] && [ -z "$build2" ]; then return 0; fi
    if [ -z "$build1" ]; then COMPARE_RESULT=-1; return 0; fi
    if [ -z "$build2" ]; then COMPARE_RESULT=1; return 0; fi
    compare_versions "0.0.0-$build1" "0.0.0-$build2"
}
# Severity rank used to compare and count advisories (sets SEV_RANK).
# GHSA spells medium "moderate".
severity_rank() {
    case "${1,,}" in
        critical) SEV_RANK=4 ;;
        high) SEV_RANK=3 ;;
        medium|moderate) SEV_RANK=2 ;;
        low) SEV_RANK=1 ;;
        *) SEV_RANK=0 ;;
    esac
}

# Collect the advisories attached to a matched version/range into the
# caller's adv_list (records "severity;ghsa;cve;source;fix;id") and adv_ids
# (identity -> index). GHSA and OSV describe the same advisory in two records:
# records sharing a GHSA id, a CVE or an OSV id merge into one entry whose
# sources accumulate ("ghsa, osv") and whose missing fields are filled in.
# Two different GHSA ids never merge.
record_matching_advisories() {
    local lookup_key="$1"
    local records="${VULN_RECORDS[$lookup_key]:-}"
    local record severity ghsa cve source fix id idx key
    local s0 g0 c0 src0 f0 i0
    [ -n "$records" ] || records=";;;;;"
    while IFS= read -r record; do
        [ -n "$record" ] || continue
        IFS=';' read -r severity ghsa cve source fix id <<< "$record"
        idx=""
        if [ -n "$ghsa$cve$id" ]; then
            for key in ${ghsa:+"ghsa:$ghsa"} ${cve:+"cve:$cve"} ${id:+"id:$id"}; do
                [ -n "${adv_ids[$key]+x}" ] || continue
                idx="${adv_ids[$key]}"
                IFS=';' read -r s0 g0 c0 src0 f0 i0 <<< "${adv_list[$idx]}"
                if [ -n "$ghsa" ] && [ -n "$g0" ] && [ "$ghsa" != "$g0" ]; then
                    idx=""
                    continue
                fi
                break
            done
        elif [ -n "${adv_ids[record:$record]+x}" ]; then
            continue
        fi
        if [ -z "$idx" ]; then
            idx=${#adv_list[@]}
            adv_list+=("$record")
            [ -n "$ghsa$cve$id" ] || adv_ids["record:$record"]="$idx"
        else
            IFS=';' read -r s0 g0 c0 src0 f0 i0 <<< "${adv_list[$idx]}"
            severity_rank "$s0"; local rank0=$SEV_RANK
            severity_rank "$severity"
            [ "$SEV_RANK" -gt "$rank0" ] || severity="$s0"
            case ", $src0, " in
                *", $source, "*) source="$src0" ;;
                *) source="${src0:+$src0${source:+, }}$source" ;;
            esac
            adv_list[$idx]="$severity;${g0:-$ghsa};${c0:-$cve};$source;${f0:-$fix};${i0:-$id}"
            IFS=';' read -r severity ghsa cve source fix id <<< "${adv_list[$idx]}"
        fi
        for key in ${ghsa:+"ghsa:$ghsa"} ${cve:+"cve:$cve"} ${id:+"id:$id"}; do
            adv_ids["$key"]="$idx"
        done
    done <<< "$records"
}

# Store the merged advisories of one finding. VULN_ADVISORIES keeps them all
# ("rec||rec"); the VULN_METADATA_* summary uses the most severe advisory and
# VULN_METADATA_FIX the highest fixed version (the one that fixes them all).
finalize_advisories() {
    local result_key="$1" rec joined="" best="" best_rank=-1 fixed=""
    local severity ghsa cve source fix id
    for rec in "${adv_list[@]}"; do
        joined+="${joined:+||}$rec"
        IFS=';' read -r severity ghsa cve source fix id <<< "$rec"
        severity_rank "$severity"
        if [ "$SEV_RANK" -gt "$best_rank" ]; then best_rank=$SEV_RANK; best="$rec"; fi
        if [ -n "$fix" ]; then
            if [ -z "$fixed" ]; then
                fixed="$fix"
            else
                compare_versions_eco "$CHECK_ECO" "$fix" "$fixed"
                [ "$COMPARE_RESULT" != 1 ] || fixed="$fix"
            fi
        fi
    done
    VULN_ADVISORIES["$result_key"]="$joined"
    IFS=';' read -r severity ghsa cve source fix id <<< "$best"
    VULN_METADATA_SEVERITY["$result_key"]="$severity"
    VULN_METADATA_GHSA["$result_key"]="$ghsa"
    VULN_METADATA_CVE["$result_key"]="$cve"
    VULN_METADATA_SOURCE["$result_key"]="$source"
    VULN_METADATA_FIX["$result_key"]="$fixed"
}

# Canonical form of a user-supplied package name for an ecosystem (the form
# the lockfile parsers and feeds use). Sets CANON_NAME.
canonical_package_name() {
    case "$1" in
        pypi) _pypi_normalize_name "$2"; CANON_NAME="$PEP503_NAME" ;;
        nuget|composer|githubactions) CANON_NAME="${2,,}" ;;
        # groupId/artifactId (purl form) -> groupId:artifactId (lockfile form)
        maven) CANON_NAME="${2//\//:}" ;;
        swift)
            local n="${2,,}"
            n="${n#*://}"; n="${n%/}"; n="${n%.git}"
            CANON_NAME="$n" ;;
        *) CANON_NAME="$2" ;;
    esac
}

# Probe ecosystem-specific and wildcard feeds without cross-ecosystem leakage.
# Args: ecosystem package version source-file. With --package-name, only that
# package (PACKAGE_FILTER = "eco:name") is reported.
check_vulnerability() {
    local eco="$1" name="$2" version="$3" source="$4"
    if [ -n "${PACKAGE_FILTER:-}" ] && [ "$eco:$name" != "$PACKAGE_FILTER" ]; then
        return 1
    fi
    # Most installed packages have no advisory. Avoid allocating per-advisory
    # maps and parsing four empty lists for every such dependency in a lockfile.
    # Wildcard sources (CSV, JSON, reports without a purl) keep names as their
    # author wrote them: they are keyed by a loose form (lowercase, runs of
    # - _ . as one "-", see loose_name in AWK_FEED_LIB), probed the same way.
    local loose="${name,,}"
    loose="${loose//[_.]/-}"
    while [[ "$loose" == *--* ]]; do loose="${loose//--/-}"; done
    if [ -z "${VULN_EXACT_LOOKUP[$eco:$name]+x}" ] &&
        [ -z "${VULN_RANGE_LOOKUP[$eco:$name]+x}" ] &&
        [ -z "${VULN_EXACT_LOOKUP[*:$loose]+x}" ] &&
        [ -z "${VULN_RANGE_LOOKUP[*:$loose]+x}" ]; then
        return 1
    fi
    CHECK_ECO="$eco"
    local result_key="${eco}:${name}@${version}"
    local -a probe_keys=("${eco}:${name}")
    [ "$eco" = "*" ] || probe_keys+=("*:${loose}")
    local pk candidate lookup_key message="" found=false
    local -a candidates
    local -A seen_candidates=() adv_ids=()
    local -a adv_list=()
    local collect=true
    [ -z "${VULN_ADVISORIES[$result_key]+x}" ] || collect=false

    for pk in "${probe_keys[@]}"; do
        IFS='|' read -ra candidates <<< "${VULN_EXACT_LOOKUP[$pk]:-}"
        for candidate in "${candidates[@]}"; do
            [ -n "$candidate" ] || continue
            lookup_key="${pk}@${candidate}"
            [ -z "${seen_candidates[$lookup_key]+x}" ] || continue
            seen_candidates["$lookup_key"]=1
            if version_matches_vulnerable "$version" "$candidate"; then
                if [ "$found" = false ]; then
                    if [ "$version" = "$candidate" ]; then
                        message="(vulnerable)"
                    else
                        message="(vulnerable - pre-release of $candidate)"
                    fi
                fi
                found=true
                if [ "$collect" = true ]; then
                    record_matching_advisories "$lookup_key"
                fi
            fi
        done

        # Newlines separate complete ranges, preserving OR (||) expressions.
        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            lookup_key="${pk}:${candidate}"
            [ -z "${seen_candidates[$lookup_key]+x}" ] || continue
            seen_candidates["$lookup_key"]=1
            if version_in_range "$version" "$candidate"; then
                if [ "$found" = false ]; then
                    message="(vulnerable - matches range: $candidate)"
                fi
                found=true
                if [ "$collect" = true ]; then
                    record_matching_advisories "$lookup_key"
                fi
            fi
        done <<< "${VULN_RANGE_LOOKUP[$pk]:-}"
    done

    if [ "$found" = true ]; then
        [ "$collect" = false ] || finalize_advisories "$result_key"
        echo -e "${RED}⚠️  [$source] $name@$version $message${NC}"
        FOUND_VULNERABLE=1
        VULNERABLE_PACKAGES+=("$source|$eco|$name@$version")
        return 0
    fi
    return 1
}
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
# ============================================================================
# Ecosystem registry — single source of truth for lockfile discovery/dispatch.
#
# Each entry: "basename|purl-type|parser-function|type-alias"
#   basename        exact lockfile filename matched with `find -name`
#   purl-type       ecosystem namespace passed to check_vulnerability and used
#                   to resolve per-ecosystem default feeds (ghsa-<eco>.purl)
#   parser-function analyzer invoked as: <fn> <lockfile> <purl-type>
#   type-alias      user-facing name for --lockfile-types / --ecosystems
#
# Support for a new ecosystem is added by APPENDING one line here (plus the
# matching parser file). Keep the npm rows first so the derived find-pattern
# order stays byte-identical to the legacy hardcoded list.
#
# GitHub Actions is discovered by PATH (.github/workflows/*.yml|*.yaml), not by
# a fixed lockfile basename, so it is declared in the parallel
# PATH_ECOSYSTEM_REGISTRY below — NOT as a row in this table, whose derivations
# all assume a fixed filename (find `-name`, basename dispatch, and the GitHub
# code-search filename list). This file is the ONE place both registries live;
# discover_project_files and the main() dispatch loop special-case path entries
# via path_ecosystem_match (parser: src/50-ecosystems/60-actions.sh).
# ============================================================================
ECOSYSTEM_REGISTRY=(
    "package-lock.json|npm|analyze_package_lock|npm"
    "npm-shrinkwrap.json|npm|analyze_package_lock|npm"
    "yarn.lock|npm|analyze_yarn_lock|yarn"
    "pnpm-lock.yaml|npm|analyze_pnpm_lock|pnpm"
    "bun.lock|npm|analyze_bun_lock|bun"
    "deno.lock|npm|analyze_deno_lock|deno"
    "Cargo.lock|cargo|analyze_toml_pkg_lock|rust"
    "go.sum|golang|analyze_go_sum|go"
    "go.mod|golang|analyze_go_mod|go"
    "requirements.txt|pypi|analyze_requirements_txt|python"
    "poetry.lock|pypi|analyze_toml_pkg_lock|python"
    "uv.lock|pypi|analyze_toml_pkg_lock|python"
    "pdm.lock|pypi|analyze_toml_pkg_lock|python"
    "Pipfile.lock|pypi|analyze_pipfile_lock|python"
    "Gemfile.lock|gem|analyze_gemfile_lock|ruby"
    "composer.lock|composer|analyze_composer_lock|php"
    "gradle.lockfile|maven|analyze_gradle_lockfile|maven"
    "pom.xml|maven|analyze_pom_xml|maven"
    "packages.lock.json|nuget|analyze_nuget_lock|nuget"
    "pubspec.lock|pub|analyze_pubspec_lock|dart"
    "mix.lock|hex|analyze_mix_lock|hex"
    "Package.resolved|swift|analyze_package_resolved|swift"
)

# ============================================================================
# Path-discovered ecosystems — the parallel to ECOSYSTEM_REGISTRY for
# ecosystems selected by a directory PATH pattern or a filename glob instead of
# a fixed lockfile basename. GitHub Actions workflow YAML lives at a well-known
# path (.github/workflows/*.yml|*.yaml) under ARBITRARY filenames, and pip
# projects split pins into requirements-*.txt or requirements/*.txt, so `find
# -name <basename>` cannot select them and `basename` cannot dispatch them. Both the find-args
# builder and the dispatcher special-case these entries (see discover_project_files
# and the analysis loop in src/90-main.sh); path_ecosystem_match() below is the
# single resolver they share.
#
# Each entry: "path-glob|name-globs|purl-type|parser-function|type-alias"
#   path-glob        find -path pattern selecting the containing directory
#   name-globs       comma-separated -name patterns (OR-ed) for the filename
#   purl-type        ecosystem namespace (as in ECOSYSTEM_REGISTRY)
#   parser-function  analyzer invoked as: <fn> <file> <purl-type>
#   type-alias       user-facing --lockfile-types / --ecosystems name
#
# NOTE: path ecosystems are deliberately absent from ecosystem_scan_filenames()
# (the GitHub org-scan search) — matching arbitrary-named workflow YAML across a
# whole repo tree via the code-search API is too noisy — so GitHub org scanning
# does not fetch workflow files. This is a documented limitation.
PATH_ECOSYSTEM_REGISTRY=(
    "*/.github/workflows/*|*.yml,*.yaml|githubactions|analyze_github_workflow|actions"
    "*|requirements-*.txt|pypi|analyze_requirements_txt|python"
    "*/requirements/*|*.txt|pypi|analyze_requirements_txt|python"
)

# Resolve a discovered file to its path-ecosystem. Echoes "parser|eco|alias"
# for the FIRST PATH_ECOSYSTEM_REGISTRY entry whose path-glob matches $1 and one
# of whose name-globs matches its basename; returns non-zero with no output when
# nothing matches. Shared by the detection loop and the dispatcher so a workflow
# file routes to its analyzer without a basename key. `case` patterns are used
# (not filesystem globbing): the name-globs are read via IFS to avoid pathname
# expansion, and `$glob`/`$path_glob` act as pattern metacharacters in `case`.
path_ecosystem_match() {
    # NB: separate declarations — `local file=.. base=${file##*/}` would expand
    # base against file's OUTER value (bash evaluates all `local` args before
    # assigning), yielding an empty basename.
    local file="$1"
    local base="${file##*/}"
    local entry path_glob name_globs eco parser alias glob
    local -a globs
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r path_glob name_globs eco parser alias <<< "$entry"
        # SC2254: $path_glob is INTENTIONALLY unquoted so it acts as a glob
        # pattern (e.g. */.github/workflows/*), not a literal string.
        # shellcheck disable=SC2254
        case "$file" in
            $path_glob) ;;
            *) continue ;;
        esac
        IFS=',' read -ra globs <<< "$name_globs"
        for glob in "${globs[@]}"; do
            # SC2254: $glob is INTENTIONALLY unquoted so *.yml / *.yaml match as
            # patterns rather than literal filenames.
            # shellcheck disable=SC2254
            case "$base" in
                $glob) printf '%s|%s|%s\n' "$parser" "$eco" "$alias"; return 0 ;;
            esac
        done
    done
    return 1
}

# Derive the per-basename lookup tables from ECOSYSTEM_REGISTRY. Called once
# near the top of main(). Fills LOCKFILE_PARSER / LOCKFILE_ECO / LOCKFILE_ALIAS
# (keyed by basename) and KNOWN_LOCKFILE_ALIASES (space-separated unique list).
build_ecosystem_tables() {
    LOCKFILE_PARSER=()
    LOCKFILE_ECO=()
    LOCKFILE_ALIAS=()
    KNOWN_LOCKFILE_ALIASES=""

    local entry basename eco parser alias
    for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r basename eco parser alias <<< "$entry"
        LOCKFILE_PARSER["$basename"]="$parser"
        LOCKFILE_ECO["$basename"]="$eco"
        LOCKFILE_ALIAS["$basename"]="$alias"

        # Append alias to KNOWN_LOCKFILE_ALIASES only if not already present
        case " $KNOWN_LOCKFILE_ALIASES " in
            *" $alias "*) ;;
            *) KNOWN_LOCKFILE_ALIASES="${KNOWN_LOCKFILE_ALIASES:+$KNOWN_LOCKFILE_ALIASES }$alias" ;;
        esac
    done

    # Path-discovered ecosystems contribute their type-alias to the known list
    # too (so --lockfile-types actions and --ecosystems actions validate), but
    # NO basename rows in the LOCKFILE_* maps — they dispatch by path via
    # path_ecosystem_match(), not by a basename lookup.
    local pglob nglobs
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r pglob nglobs eco parser alias <<< "$entry"
        case " $KNOWN_LOCKFILE_ALIASES " in
            *" $alias "*) ;;
            *) KNOWN_LOCKFILE_ALIASES="${KNOWN_LOCKFILE_ALIASES:+$KNOWN_LOCKFILE_ALIASES }$alias" ;;
        esac
    done
}

# Filenames GitHub discovery should fetch: package.json (scanned but NOT a
# registry row) followed by every registry basename, in registry order.
# Space-separated (filenames contain no spaces).
ecosystem_scan_filenames() {
    local names="package.json" entry
    for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
        names="$names ${entry%%|*}"
    done
    printf '%s' "$names"
}

# Map a --ecosystems / --lockfile-types token to a purl type. Registry aliases
# resolve to their purl-type; anything else passes through unchanged (callers
# validate the result separately).
ecosystem_alias_to_purl() {
    local token="$1" entry basename eco parser alias pglob nglobs
    for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r basename eco parser alias <<< "$entry"
        if [ "$token" = "$alias" ]; then
            printf '%s\n' "$eco"
            return 0
        fi
    done
    # Path-discovered ecosystems (e.g. actions -> githubactions).
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r pglob nglobs eco parser alias <<< "$entry"
        if [ "$token" = "$alias" ]; then
            printf '%s\n' "$eco"
            return 0
        fi
    done
    printf '%s\n' "$token"
}

# Default feed filename for a (feed, eco) pair.
#   npm  -> ghsa.purl / osv.purl        (legacy names, unchanged)
#   else -> ghsa-<eco>.purl / osv-<eco>.purl
default_feed_filename() {
    local feed="$1" eco="$2"
    if [ "$eco" = "npm" ]; then
        printf '%s.purl\n' "$feed"
    else
        printf '%s-%s.purl\n' "$feed" "$eco"
    fi
}
# Python / PyPI dependency parsers.
#
# Registered lockfiles (see 01-registry.sh):
#   requirements.txt, requirements-*.txt, requirements/*.txt
#                    -> analyze_requirements_txt   (exact == pins only)
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
#   * backslash continuations are joined before comments/options are stripped;
#   * requirements using any operator other than '==' (>=, <=, ~=, !=, ===, >,
#     <) are skipped — a range is not an installed version — and so are
#     wildcard pins such as ==1.0.*.
# Extracted names are PEP 503-normalized.
analyze_requirements_txt() {
    local lockfile="$1"
    local eco="${2:-pypi}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    {
        physical = $0
        sub(/\r$/, "", physical)
        # pip joins physical lines without inserting whitespace. In particular
        # a pin may be followed by several --hash options on continued lines.
        if (physical ~ /\\$/) {
            sub(/\\$/, "", physical)
            pending = pending physical
            next
        }
        line = pending physical
        pending = ""
        sub(/[[:space:]]*#.*$/, "", line)          # strip inline/full comment
        sub(/;.*$/, "", line)                       # strip PEP 508 env marker
        gsub(/^[[:space:]]+/, "", line)             # trim
        gsub(/[[:space:]]+$/, "", line)
        if (line == "") next
        if (line ~ /^-/) next                       # -r/-c/-e/--hash/--index-url
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
        if (ver ~ /\*/) next                        # ==1.0.* is a range, not a pin
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
    packages=$(json_structural_lines "$lockfile" | awk '
    {
        line = $0
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line ~ /[\{\[]$/) {
            if (depth == 1) section = (line ~ /^"(default|develop)"[[:space:]]*:/)
            if (section && depth == 2 && line ~ /^"/) {
                pkg = line
                sub(/^"/, "", pkg)
                sub(/".*/, "", pkg)
            }
            depth++
        } else if (line == "}" || line == "]") {
            depth--
            if (depth == 2) pkg = ""
            if (depth == 1) section = 0
        } else if (section && depth == 3 && pkg != "" && line ~ /^"version"[[:space:]]*:[[:space:]]*"==/) {
            sub(/^"version"[[:space:]]*:[[:space:]]*"==/, "", line)
            sub(/".*/, "", line)
            if (line != "") print pkg "|" line
        }
    }
    ' | sort -u)

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
# LOCAL PROJECTS: uv.lock lists the project being locked as a [[package]] with
# source = { editable = "." } or { virtual = "." }; such entries are skipped.
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
        if (pkg_name != "" && pkg_version != "" && !local_pkg) {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_version = ""
        local_pkg = 0
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
    # uv.lock records the project itself (and workspace members) with an
    # editable or virtual source: local code, not a published release.
    in_pkg && /^[[:space:]]*source[[:space:]]*=[[:space:]]*\{.*(editable|virtual)[[:space:]]*=/ {
        local_pkg = 1
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
# the `-<tail>` dropped. The token must be a WHOLE dash/underscore-delimited
# segment (optionally trailed by digits, e.g. `mingw32`), anchored via
# `(^|[-_])TOKEN[0-9]*([-_]|$)` — so `1.0.0-javascript` is NOT stripped just
# because `java` is a substring of `javascript`. A real prerelease dash
# (`1.0.0-rc1`) does not match any platform token either, so it is left alone
# (RubyGems itself treats `-` as a prerelease separator; see compare_versions_gem).
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
            if (suffix ~ /(^|[-_])(x86_64|aarch64|arm64|universal|java|mingw|mswin|darwin|linux|freebsd)[0-9]*([-_]|$)/) {
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
# PHP (Composer) dependency parser.
#
#   composer.lock -> analyze_composer_lock
#
# composer.lock is plain JSON (no jq available/allowed on the scan path), and
# unlike package-lock.json's flat "node_modules/x": {...} map, its packages
# live in TWO top-level arrays: "packages" (production) and "packages-dev"
# (require-dev). Each array element is a package object with MANY sibling
# keys beyond name/version (source, dist, require, require-dev, provide,
# suggest, type, extra, autoload, notification-url, license, authors,
# description, homepage, keywords, support, funding, time, ...), several of
# which are themselves nested objects/arrays. Notably "authors" is an array
# of {"name": ..., "email": ..., ...} objects, so a naive "capture name, then
# capture the next version" state machine (as used for package-lock.json)
# would risk a nested author's "name" clobbering the package name, or -
# worse - would never be at risk of finding a stray "version" key deeper in
# (composer.lock has no "version" key inside require/source/dist/authors/
# support/funding), but relying on that emptily is fragile. Instead this
# parser tracks JSON brace/bracket DEPTH precisely (one increment per `{`/`[`,
# one decrement per `}`/`]`, quoted-string contents skipped so punctuation
# inside URLs/descriptions/names never miscounts) so that "name"/"version"
# are only captured when they are DIRECT fields of a package object (exactly
# one level below the "packages"/"packages-dev" array) - any subtable
# (source/dist/require/autoload/authors/support/funding/...) sits at least
# one level deeper and is excluded, mirroring the TOML [[package]] parser's
# subtable-gap hardening (src/50-ecosystems/20-rust.sh) but for JSON nesting
# instead of TOML headers. The pending name/version pair is emitted the
# instant the enclosing package object's closing brace is seen, so it does
# not matter how many nested keys/objects a real entry has in between.
#
# json_structural_lines splits JSON outside strings before depth tracking,
# so compact JSON and Composer-generated pretty JSON have the same records.
#
# NORMALIZATION: package names are lowercased (composer canon is
# "vendor/package", already lowercase on the feed side - data/ghsa-composer.purl
# / data/osv-composer.purl - so this keeps a mixed-case lockfile entry, if
# one is ever seen in the wild, matching). Versions have a leading "v"
# stripped (some vendors tag "v7.4.0"; compare_versions_eco routes composer
# through the plain semver comparator, which expects a bare "7.4.0" - see
# src/40-versions/01-dispatch.sh) and "dev-*" branch aliases (e.g.
# "dev-master", "dev-feature/x" - not a resolvable release, no advisory can
# target it) are skipped silently, same as npm parsers skip workspace/link
# deps and pypi skips VCS entries without a resolvable version.
analyze_composer_lock() {
    local lockfile="$1"
    local eco="${2:-composer}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(json_structural_lines "$lockfile" | awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "") {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_version = ""
    }
    BEGIN {
        depth = 0
        in_pkgs = 0
        pkg_depth = -1
    }
    {
        line = $0
        start_depth = depth

        # Enter a "packages" / "packages-dev" array at the CURRENT (pre-line)
        # depth. Guarded by !in_pkgs so the same literal text appearing
        # inside an already-open packages array (e.g. in a description
        # string) cannot re-trigger this.
        if (!in_pkgs && match(line, /"packages(-dev)?"[[:space:]]*:[[:space:]]*\[/)) {
            in_pkgs = 1
            pkg_depth = start_depth + 1
            pkg_name = ""
            pkg_version = ""
        }

        # Only DIRECT fields of a package object (one level below the array)
        # are candidate name/version lines; any nested object/array (source,
        # dist, require, provide, suggest, extra, autoload, authors,
        # support, funding, ...) sits at pkg_depth+2 or deeper and is
        # excluded by this check.
        if (in_pkgs && start_depth == pkg_depth + 1) {
            if (match(line, /^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_name = tolower(temp)
            } else if (match(line, /^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "" && temp !~ /^dev-/) {
                    sub(/^v/, "", temp)
                    pkg_version = temp
                }
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the
        # pending package the instant its object closes and closing the
        # array itself once depth falls back below pkg_depth.
        n = length(line)
        in_str = 0
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            if (in_str) {
                if (c == "\\") { i++ }
                else if (c == "\"") { in_str = 0 }
                continue
            }
            if (c == "\"") { in_str = 1; continue }
            if (c == "{" || c == "[") {
                depth++
            } else if (c == "}" || c == "]") {
                depth--
                if (in_pkgs && depth == pkg_depth) {
                    emit_pkg()
                } else if (in_pkgs && depth < pkg_depth) {
                    in_pkgs = 0
                    pkg_depth = -1
                    pkg_name = ""
                    pkg_version = ""
                }
            }
        }
    }
    END { emit_pkg() }
    ' | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
# Maven (JVM) dependency parsers.
#
#   gradle.lockfile -> analyze_gradle_lockfile   (Gradle's resolved dependency lock)
#   pom.xml         -> analyze_pom_xml           (Maven manifest, direct deps)
#
# Canonical package identity is "groupId:artifactId" (the ONLY ecosystem whose
# canonical names contain a ':'). This matches the feed emission: the purl parser
# canonicalizes pkg:maven/groupId/artifactId to the key "maven:groupId:artifactId"
# (canon_purl_name joins the last two path components with ':', see
# src/31-parsers-purl.sh), and check_vulnerability probes "maven:<name>", so a
# parser that emits "groupId:artifactId" lines up exactly. Versions are passed
# through verbatim and ordered by compare_versions_maven (ComparableVersion).

# Parse a gradle.lockfile. Format (one dependency per line):
#   group:artifact:version=conf1,conf2,...
# plus a header comment block (lines starting with '#') and a trailing sentinel
#   empty=conf,...
# listing configurations that resolved to nothing. Comments and the "empty="
# sentinel carry no package, so they are skipped. The key (left of '=') splits on
# ':' into exactly group / artifact / version (Maven coordinates never contain a
# ':' in any single component), so a line that does not split into three is not a
# coordinate and is ignored.
analyze_gradle_lockfile() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    {
        line = $0
        gsub(/\r/, "", line)                       # tolerate CRLF checkouts
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line == "") next
        if (line ~ /^#/) next                      # header comment lines
        eq = index(line, "=")
        if (eq == 0) next
        key = substr(line, 1, eq - 1)
        if (key == "empty") next                   # "empty=" sentinel
        n = split(key, a, ":")
        if (n != 3) next                           # not a group:artifact:version
        if (a[1] == "" || a[2] == "" || a[3] == "") next
        print a[1] ":" a[2] "|" a[3]
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

# Parse a pom.xml. The whole file is read into one string so tags split over
# several lines (<version>\n  1.2.3\n</version>) parse like single-line ones,
# and XML comments are removed first (a commented-out <dependency> is not a
# dependency). Each <dependency> block yields its <groupId>, <artifactId> and
# <version>; nested <exclusions> are cut out so their coordinates cannot
# clobber the dependency's. A version "${name}" is resolved from the same
# file's <properties>; anything else that is not a literal version is SKIPPED:
# unresolved properties (parent POMs, ${project.version}), dependencyManagement
# inheritance (no version at all) and version ranges ("[1.0,2.0)"). This is a
# manifest-grade parser — the same class of limitation every non-lockfile
# parser in this codebase carries; the missing and unresolved versions are
# counted and reported once, pointing to --sbom. <dependency> blocks anywhere are accepted
# (project <dependencies> and <dependencyManagement> alike); the opening tag is
# matched as "<dependency" followed by a space or '>' so that the
# "<dependencies>" wrapper never opens a block.
analyze_pom_xml() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    # Inner text of the first <tag>...</tag> in s, or "\001" when absent.
    function inner(s, tag,   open, b, rest, e) {
        open = "<" tag ">"
        b = index(s, open)
        if (b == 0) return "\001"
        rest = substr(s, b + length(open))
        e = index(rest, "</" tag ">")
        if (e == 0) return "\001"
        return trim(substr(rest, 1, e - 1))
    }
    { doc = doc $0 "\n" }
    END {
        gsub(/\r/, "", doc)
        # Drop XML comments (an unterminated one runs to the end of file).
        while ((b = index(doc, "<!--")) > 0) {
            rest = substr(doc, b + 4)
            e = index(rest, "-->")
            doc = substr(doc, 1, b - 1) (e ? substr(rest, e + 3) : "")
        }
        # <properties><name>value</name>...</properties>
        props = inner(doc, "properties")
        if (props != "\001") {
            while (match(props, /<[A-Za-z0-9_.-]+>[^<]*<\//)) {
                m = substr(props, RSTART + 1, RLENGTH - 3)
                gt = index(m, ">")
                prop[substr(m, 1, gt - 1)] = trim(substr(m, gt + 1))
                props = substr(props, RSTART + RLENGTH)
            }
        }
        rest = doc
        while (match(rest, /<dependency[[:space:]>]/)) {
            rest = substr(rest, RSTART + RLENGTH)
            e = index(rest, "</dependency>")
            if (e == 0) break
            block = substr(rest, 1, e - 1)
            rest = substr(rest, e + 13)
            while ((b = index(block, "<exclusions>")) > 0) {
                x = index(substr(block, b), "</exclusions>")
                block = substr(block, 1, b - 1) (x ? substr(block, b + x + 12) : "")
            }
            g = inner(block, "groupId"); a = inner(block, "artifactId"); v = inner(block, "version")
            if (g == "\001" || a == "\001" || g == "" || a == "") continue
            if (v ~ /^\$\{[^}]+\}$/) {
                name = substr(v, 3, length(v) - 3)
                v = (name in prop) ? prop[name] : ""
            }
            # Missing or unresolved versions come from a parent POM or a BOM.
            if (v == "\001" || v == "" || index(v, "${")) { unversioned++; continue }
            # Version ranges are not installed versions.
            if (v ~ /^[\[(]/ || index(v, ",")) continue
            print g ":" a "|" v
        }
        # "-" is never a groupId:artifactId: it carries the unversioned count.
        if (unversioned) print "-|" unversioned
    }
    ' "$lockfile" 2>/dev/null | sort -u)

    local unversioned=0
    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        if [ "$pkg_name" = "-" ]; then unversioned="$version"; continue; fi
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    if [ "$unversioned" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  $unversioned dependencies in $lockfile have no version here (managed by a parent POM or BOM): scan a CycloneDX SBOM with --sbom (cyclonedx-maven-plugin) or a gradle.lockfile to check them${NC}"
    fi

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
# NuGet dependency parser.
#
#   packages.lock.json -> analyze_nuget_lock
#
# (csproj is a tier-2 manifest — no manifest-grade property/MSBuild-condition
# resolution is attempted anywhere else in this codebase either, see pom.xml's
# ${property} skip — so it is NOT registered/parsed at all.)
#
# packages.lock.json is plain JSON (no jq on the scan path) shaped THREE
# levels deep below the root: a single top-level "dependencies" object keyed
# by target framework moniker (e.g. "net8.0"; a multi-targeted project has one
# sibling object per TFM), each holding package-name-keyed objects with a
# "type" ("Direct" | "Transitive" | "CentralTransitive" | "Project") and,
# except for Project, a "resolved" version. CentralTransitive marks transitive
# packages pinned through Central Package Management (Directory.Packages.props). This is one nesting level deeper than composer.lock's
# "packages"/"packages-dev" ARRAY of objects (src/50-ecosystems/30-php.sh), so
# the same JSON brace/bracket DEPTH-TRACKING approach is used here but against
# TWO thresholds instead of composer's one: package names are only captured
# at "framework object contents" depth (deps_depth + 1) and "type"/"resolved"
# fields only at "package object contents" depth (deps_depth + 2). This
# precision matters because a Transitive (or Project) entry commonly carries
# its OWN nested "dependencies" sub-object (name -> requested-range STRING,
# not an object with a "resolved" field) one level deeper still, e.g.:
#   "Serilog.Sinks.Console": {
#     "type": "Transitive", "resolved": "4.1.0",
#     "dependencies": { "Serilog": "3.1.1" }
#   }
# A depth-exact parser skips straight past that nested map (it never reaches
# the field-capture depth), so it can never be mistaken for another package
# or clobber the enclosing entry's own type/resolved - the identical class of
# hardening composer.lock's parser applies to "authors"/"require"/"support".
#
# "type": "Project" entries (an in-solution ProjectReference resolved through
# the lock file, e.g. a referenced class library) carry NO "resolved" field
# at all, so they are skipped by construction: emit_pkg() only prints when
# type is Direct, Transitive or CentralTransitive AND a resolved version was
# captured.
#
# NORMALIZATION: package names (the JSON keys themselves) are LOWERCASED
# (NuGet canon - the feed side, data/ghsa-nuget.purl / data/osv-nuget.purl,
# and canon_purl_name() in src/31-parsers-purl.sh, both lowercase nuget names
# already; composer/githubactions share this same canon). Versions are passed
# through verbatim - real "resolved" values are always a bare
# Major.Minor.Patch[.Revision][-prerelease] with no "v" prefix, ordered by
# compare_versions_nuget (src/40-versions/25-nuget.sh).
#
# DEDUPE: a multi-targeted project (TargetFrameworks with more than one TFM)
# repeats every package once per framework block; identical name|version
# pairs collapse via the same `sort -u` every other parser in this codebase
# uses, so a package resolving to the SAME version under both frameworks is
# reported (and checked) exactly once.
analyze_nuget_lock() {
    local lockfile="$1"
    local eco="${2:-nuget}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(json_structural_lines "$lockfile" | awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "" && (pkg_type == "Direct" || pkg_type == "Transitive" || pkg_type == "CentralTransitive")) {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_type = ""
        pkg_version = ""
    }
    BEGIN {
        depth = 0
        in_deps = 0
        deps_depth = -1
    }
    {
        line = $0
        gsub(/\r/, "", line)                        # tolerate CRLF checkouts
        start_depth = depth

        # Enter the top-level "dependencies" object at the CURRENT (pre-line)
        # depth. Guarded by !in_deps so a package'\''s own nested "dependencies"
        # sub-object (requested-range strings, no "type"/"resolved" fields -
        # see header) cannot re-trigger this once already inside.
        if (!in_deps && match(line, /"dependencies"[[:space:]]*:[[:space:]]*\{/)) {
            in_deps = 1
            deps_depth = start_depth + 1
            pkg_name = ""
            pkg_type = ""
            pkg_version = ""
        }

        # Package-name keys live one level inside each framework object
        # (deps_depth + 1): "PackageId": { opens a new package entry.
        if (in_deps && start_depth == deps_depth + 1) {
            if (match(line, /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*\{/)) {
                temp = line
                sub(/^[[:space:]]*"/, "", temp)
                sub(/"[[:space:]]*:[[:space:]]*\{.*$/, "", temp)
                if (temp != "") {
                    pkg_name = tolower(temp)
                    pkg_type = ""
                    pkg_version = ""
                }
            }
        }

        # "type"/"resolved" are DIRECT fields of a package object, one level
        # deeper still (deps_depth + 2); a nested per-package "dependencies"
        # map (see header) sits at deps_depth + 3 and is excluded by this
        # check regardless of its own key names.
        if (in_deps && start_depth == deps_depth + 2) {
            if (match(line, /^[[:space:]]*"type"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"type"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_type = temp
            } else if (match(line, /^[[:space:]]*"resolved"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"resolved"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_version = temp
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the pending
        # package the instant its object closes (back to deps_depth + 1),
        # resetting stray state when a framework object closes (deps_depth),
        # and closing "dependencies" itself once depth falls below deps_depth.
        n = length(line)
        in_str = 0
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            if (in_str) {
                if (c == "\\") { i++ }
                else if (c == "\"") { in_str = 0 }
                continue
            }
            if (c == "\"") { in_str = 1; continue }
            if (c == "{" || c == "[") {
                depth++
            } else if (c == "}" || c == "]") {
                depth--
                if (in_deps && depth == deps_depth + 1) {
                    emit_pkg()
                } else if (in_deps && depth == deps_depth) {
                    pkg_name = ""
                    pkg_type = ""
                    pkg_version = ""
                } else if (in_deps && depth < deps_depth) {
                    in_deps = 0
                    deps_depth = -1
                    pkg_name = ""
                    pkg_type = ""
                    pkg_version = ""
                }
            }
        }
    }
    END { emit_pkg() }
    ' | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
# Dart/Flutter (pub) dependency parser.
#
#   pubspec.lock -> analyze_pubspec_lock
#
# pubspec.lock is YAML, generated by `dart pub get` / `flutter pub get`. Shape
# (indentation is significant and exact, 2 spaces per level):
#
#   packages:                        column-0, opens the block we care about
#     dio:                             2-space  <- package name key
#       dependency: "direct main"        4-space
#       description:                     4-space
#         name: dio                        6-space (nested map, ignored)
#         sha256: "…"                      6-space
#         url: "https://pub.dev"           6-space
#       source: hosted                   4-space  <- HOSTED packages only
#       version: "4.0.6"                  4-space  <- always double-quoted
#   sdks:                             column-0, closes the block
#     dart: ">=3.0.0 <4.0.0"
#     flutter: ">=3.10.0"
#
# Only `source: hosted` packages (pulled from pub.dev, or a self-hosted pub
# server) resolve to a checkable name+version pair. `source: git` (a VCS
# dependency pinned by commit, description holds url/ref/resolved-ref instead
# of name/sha256/url) and `source: path` (a local filesystem dependency) are
# both skipped the same way npm/ruby parsers skip link:/git-sourced deps — no
# pub.dev release to compare against advisories. `source: sdk` (the `flutter`
# and `dart` pseudo-packages the SDK itself provides) is skipped for the same
# reason. Because the emit only fires when source == "hosted" was seen, all
# three are excluded by construction; no explicit skip-list needed.
#
# The exactly-4-space checks (`^    source:` / `^    version:`) are what tell
# a package's OWN source/version apart from anything nested inside its
# 6-space "description:" sub-map: a 6-space line still starts with 4 spaces,
# but its 5th character is ALSO a space, so it fails to match the literal
# "source:"/"version:" that follows the 4-space prefix in the regex.
#
# The block ends at the next 2-space package key (flush + start a new one) or
# at the top-level "sdks:" key (flush + stop): both close the currently-open
# package the same way a `[[package]]` header change flushes Cargo.lock's
# TOML parser.
analyze_pubspec_lock() {
    local lockfile="$1"
    local eco="${2:-pub}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_source == "hosted" && pkg_version != "") {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_source = ""
        pkg_version = ""
    }
    BEGIN { in_packages = 0 }
    {
        gsub(/\r/, "", $0)                     # tolerate CRLF checkouts
    }
    # Top-level "packages:" key opens the block we scan.
    /^packages:[[:space:]]*$/ {
        in_packages = 1
        next
    }
    # Any OTHER column-0 (unindented) line — "sdks:" in practice, but treated
    # generically like every other YAML-block parser in this codebase — flushes
    # the pending package and closes the block for good.
    in_packages && /^[A-Za-z]/ {
        emit_pkg()
        in_packages = 0
        next
    }
    !in_packages { next }
    # 2-space package-name key: flush the previous package, start this one.
    /^  [A-Za-z0-9_]+:[[:space:]]*$/ {
        emit_pkg()
        line = $0
        sub(/^  /, "", line)
        sub(/:[[:space:]]*$/, "", line)
        pkg_name = line
        next
    }
    # 4-space "source: hosted" — git/path/sdk sources are simply never set,
    # so emit_pkg()s guard (pkg_source == "hosted") skips them by construction.
    /^    source:[[:space:]]*hosted[[:space:]]*$/ {
        pkg_source = "hosted"
        next
    }
    # 4-space "version: \"x.y.z\"" — always double-quoted in a real lockfile.
    /^    version:[[:space:]]*"/ {
        line = $0
        sub(/^    version:[[:space:]]*"/, "", line)
        sub(/".*$/, "", line)
        pkg_version = line
        next
    }
    END { emit_pkg() }
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
# Hex (Elixir/Erlang) dependency parser.
#
#   mix.lock -> analyze_mix_lock
#
# mix.lock is a literal Elixir map, generated by `mix deps.get`, ONE entry per
# line (Mix always emits it pre-sorted and pre-formatted this way; hand-edits
# are never expected to survive `mix deps.get` re-running). Shape:
#
#   %{
#     "jason": {:hex, :jason, "1.4.1", "<64-hex outer checksum>", [:mix], [{:decimal, "~> 1.0", [hex: :decimal, repo: "hexpm", optional: true]}], "hexpm", "<64-hex inner checksum>"},
#     "internal_auth": {:git, "https://github.com/example-org/internal_auth.git", "<40-hex commit sha>", []},
#   }
#
# Unlike every other lockfile in this codebase, this is NOT a block/indent
# structure to track — each dependency is already a complete, self-contained
# line, so a single per-line regex match is enough (no BEGIN/state-machine,
# no emit_pkg() flush-on-boundary dance).
#
# Only `{:hex, ...}` tuples (packages resolved from the hex.pm/private hex
# registry) are checkable. `{:git, ...}` tuples (and, per the same Mix
# resolver, `{:path, ...}` / `{:in_umbrella, ...}` — not modeled here since
# they never even reach a `{:hex,`-shaped line) pin a VCS ref or local sibling
# app instead, with no hex.pm release to compare against advisories — skipped
# the same way npm/ruby/dart parsers skip link:/git/path-sourced deps. Because
# the match anchor below REQUIRES the literal `{:hex,` immediately after the
# name key, git/path lines simply never match; no explicit skip-list needed.
#
# EXTRACTION: the second tuple element is the Hex package name. The map key
# is the application name and may differ when a dependency uses :hex. The
# version is the FIRST quoted string AFTER the
# literal `{:hex,` tuple tag and its `:atom_name,` element — i.e. the 3rd
# tuple element, `"1.2.3"` in `{:hex, :name, "1.2.3", ...}`. The checksum
# fields, `[:mix]` build-tools list, and dependency sub-list are all ignored.
#
# NORMALIZATION: none. Hex package names are used as-is (same canon as
# npm/golang/cargo/gem/pub — see canon_purl_name() in src/31-parsers-purl.sh),
# matching hex.pm's own case-sensitive package naming.
analyze_mix_lock() {
    local lockfile="$1"
    local eco="${2:-hex}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    # Anchor: a quoted map key followed by a literal `{:hex,` tuple tag.
    # `{:git, ...}` (and any other non-hex tuple) lines simply never match
    # this pattern, so they are excluded by construction.
    /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*\{:hex,/ {
        line = $0

        # Walk past "{:hex," then past the ":atom_name," element to reach
        # the tuple'\''s 3rd element, whose FIRST quoted string is the version.
        hexpos = index(line, "{:hex,")
        if (hexpos == 0) next
        rest = substr(line, hexpos + 6)
        commapos = index(rest, ",")
        if (commapos == 0) next
        name = substr(rest, 1, commapos - 1)
        gsub(/^[[:space:]]*:|[[:space:]]+$/, "", name)
        gsub(/^"|"$/, "", name)
        rest = substr(rest, commapos + 1)
        if (!match(rest, /"[^"]+"/)) next
        ver = substr(rest, RSTART + 1, RLENGTH - 2)

        if (name != "" && ver != "") print name "|" ver
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
# Swift Package Manager dependency parser.
#
#   Package.resolved -> analyze_package_resolved
#
# Package.resolved is plain JSON, in ONE of two shapes depending on the
# swift-tools-version that generated it:
#
#   v2/v3 (Swift 5.4+): pins live directly at the top level.
#     {
#       "pins" : [
#         {
#           "identity" : "swift-nio",
#           "kind" : "remoteSourceControl",
#           "location" : "https://github.com/apple/swift-nio.git",
#           "state" : { "revision" : "...", "version" : "2.10.0" }
#         }
#       ],
#       "version" : 2
#     }
#
#   v1 (swift-tools-version < 5.4): pins are nested one level deeper, under
#   "object", and the URL field is named "repositoryURL" instead of
#   "location" ("identity" is spelled "package" too, but neither name field
#   is ever read — see NORMALIZATION below).
#     {
#       "object" : { "pins" : [
#         { "package" : "swift-nio", "repositoryURL" : "https://github.com/apple/swift-nio.git",
#           "state" : { "branch" : null, "revision" : "...", "version" : "2.10.0" } }
#       ] },
#       "version" : 1
#     }
#
# Rather than branching on the top-level "version" field, this parser tracks
# brace/bracket DEPTH (the same technique packages.lock.json's parser uses,
# src/50-ecosystems/40-nuget.sh) starting from wherever the "pins" key is
# found — v1's extra "object" nesting simply shifts every depth down by one,
# which the relative tracking below absorbs for free, so both shapes are
# handled by ONE code path with no format sniffing. A pin's own direct
# fields (identity/package, kind, location/repositoryURL) are captured one
# level inside the array; its "state" sub-object is captured one level
# deeper still, where — matching either format — a `"version": "..."`
# QUOTED STRING field is required.
#
# Branch/revision-only pins (no released version — e.g. a dependency pinned
# to a branch or an exact commit) carry `"version": null` (v1) or omit the
# key entirely (v2/v3): neither satisfies the quoted-string match above, so
# ver stays empty and emit_pkg() skips the pin by construction — exactly
# like npm/dart/hex skip git/path/sdk-sourced deps that have no registry
# release to compare against advisories.
#
# NORMALIZATION (CRITICAL — must exactly match canon_purl_name's swift
# branch in src/31-parsers-purl.sh, and the feed emission in src/60-feeds.sh,
# since check_vulnerability performs no canonicalization of its own — see
# src/45-matching.sh): the package "name" checked against advisories is NOT
# the "identity"/"package" field (a short, human-picked label with no
# guaranteed uniqueness) but the resolved repository URL itself,
# canonicalized the same way GHSA/OSV swift feed rows are: strip a leading
# scheme ("https://", "ssh://git@"), rewrite the scp-like "git@host:owner/repo"
# form to "host/owner/repo", strip a trailing "/" and ".git", lowercase the
# rest. E.g. "https://GitHub.com/Apple/Swift-NIO.git" becomes
# "github.com/apple/swift-nio". This makes matching resilient to
# mixed-case GitHub URLs (GitHub itself is case-insensitive) and to
# scheme/suffix variations across manifests.
#
# Versions fall through compare_versions_eco's default (npm-semver) branch —
# swift has no dedicated comparator, src/40-versions/01-dispatch.sh — with a
# leading "v" stripped first, same as go.sum/go.mod tags
# (src/50-ecosystems/15-go.sh), since Package.swift dependency pins commonly
# resolve against tags like "v2.10.0".
analyze_package_resolved() {
    local lockfile="$1"
    local eco="${2:-swift}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(json_structural_lines "$lockfile" | awk '
    function emit_pkg() {
        if (url != "" && ver != "") {
            canon = url
            # https://host/o/r(.git)(/), ssh://git@host/o/r and the scp-like
            # git@host:o/r all name the same repository: host/o/r.
            if (sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", canon)) {
                sub(/^[^@\/]*@/, "", canon)
            } else if (sub(/^[^@\/:]*@/, "", canon)) {
                sub(/:/, "/", canon)
            }
            sub(/\/+$/, "", canon)
            sub(/\.git$/, "", canon)
            canon = tolower(canon)
            v = ver
            sub(/^v/, "", v)
            if (canon != "" && v != "") print canon "|" v
        }
        url = ""
        ver = ""
    }
    BEGIN {
        depth = 0
        in_pins = 0
        pins_depth = -1
    }
    {
        line = $0
        gsub(/\r/, "", line)                        # tolerate CRLF checkouts
        start_depth = depth

        # Enter the "pins" array wherever it appears (top level for v2/v3,
        # one level inside "object" for v1) — see header for why relative
        # depth tracking makes the two formats interchangeable here.
        if (!in_pins && match(line, /"pins"[[:space:]]*:[[:space:]]*\[/)) {
            in_pins = 1
            pins_depth = start_depth + 1
            url = ""
            ver = ""
        }

        # A pin object own direct fields, one level inside the array:
        # "location" (v2/v3) or "repositoryURL" (v1) carry the repo URL.
        if (in_pins && start_depth == pins_depth + 1) {
            if (match(line, /"location"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"location"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") url = temp
            } else if (match(line, /"repositoryURL"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"repositoryURL"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") url = temp
            }
        }

        # The pin nested "state" object, one level deeper still: only a
        # QUOTED "version" string counts — branch-only pins carry
        # "version": null (v1) or omit the key (v2/v3), neither of which
        # matches, so those pins fall through unresolved (see header).
        if (in_pins && start_depth == pins_depth + 2) {
            if (match(line, /"version"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"version"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") ver = temp
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the
        # pending pin the instant its object closes (back to pins_depth),
        # and closing the "pins" array itself once depth falls below it.
        n = length(line)
        in_str = 0
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            if (in_str) {
                if (c == "\\") { i++ }
                else if (c == "\"") { in_str = 0 }
                continue
            }
            if (c == "\"") { in_str = 1; continue }
            if (c == "{" || c == "[") {
                depth++
            } else if (c == "}" || c == "]") {
                depth--
                if (in_pins && depth == pins_depth) {
                    emit_pkg()
                } else if (in_pins && depth < pins_depth) {
                    in_pins = 0
                    pins_depth = -1
                    url = ""
                    ver = ""
                }
            }
        }
    }
    ' | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        # Primary probe: the canonical repo-URL name (github.com/owner/repo).
        local before_probe=${#VULNERABLE_PACKAGES[@]}
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
        # A few GHSA/OSV Swift advisories record the package under a bare
        # identifier (e.g. "swift-crypto") instead of the repo URL every
        # other advisory uses. Those can never match the URL-form name, so
        # when the primary probe found nothing, retry with the bare last
        # path segment as a fallback (guarded so URL-form matches always win
        # and we never double-count the same pin).
        if [ "${#VULNERABLE_PACKAGES[@]}" -eq "$before_probe" ] && [ "${pkg_name##*/}" != "$pkg_name" ]; then
            check_vulnerability "$eco" "${pkg_name##*/}" "$version" "$lockfile" || true
        fi
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
# GitHub Actions workflow parser.
#
#   .github/workflows/*.yml | *.yaml -> analyze_github_workflow
#
# UNIQUE DISCOVERY: unlike every other ecosystem in this tool, GitHub Actions is
# selected by PATH, not by a lockfile basename — workflow files live at a
# well-known location (.github/workflows/) under arbitrary names. That hook is
# declared ONCE in PATH_ECOSYSTEM_REGISTRY (src/50-ecosystems/01-registry.sh);
# discover_project_files finds the files and the main() analysis loop routes
# them here via path_ecosystem_match(). This file only implements the analyzer.
#
# WHAT IS CHECKED: the `uses:` step references that pin a published action, i.e.
# `owner/repo@ref` or `owner/repo/subpath@ref` (the latter covers subpath
# actions and reusable-workflow calls like `org/repo/.github/workflows/x.yml@ref`).
# Both the plain mapping key (`uses: ...`) and the list-item form (`- uses: ...`)
# are handled, quoted ("...") or unquoted.
#
# SKIPPED by construction:
#   * local actions  — `./path` or `../path` (no published version to check)
#   * docker images  — `docker://image:tag` (not a GitHub Action release)
#   * versionless    — `uses: owner/repo` with no `@ref` (nothing to compare)
#   * non-action     — a value with no `owner/repo`-shaped `/` before the `@`
#
# NORMALIZATION (must match canon_purl_name's githubactions branch in
# src/31-parsers-purl.sh, which lowercases, and the feed emission): the name is
# `owner/repo[/subpath]` LOWERCASED. The version is the ref with a leading `v`
# stripped when it precedes a digit (`v4.1.1` -> `4.1.1`), matching go.sum/swift
# tag handling and the semver comparator (githubactions falls through
# compare_versions_eco's default npm-semver branch, src/40-versions/01-dispatch.sh).
# Branch refs (main, release) and 40-hex commit SHAs pass through unchanged; a
# SHA-pinned ref can then only ever EXACT-match a feed entry pinned to that same
# SHA — which is fine.
#
# LIMITATIONS (documented, intentional):
#   * The `uses: owner/repo@<sha> # vX.Y.Z` version-comment convention is NOT
#     parsed — the trailing comment is stripped and the SHA is used verbatim, so
#     a SHA-pinned action is only matched by an exact-SHA advisory, not by the
#     commented semver. Keeping comment parsing out avoids a brittle heuristic.
#   * A subpath ref (`github/codeql-action/analyze@v3`) is keyed by its FULL
#     `owner/repo/subpath` name; advisories published against the base repo
#     (`github/codeql-action`) therefore do not match a subpathed `uses:`.
#   * Floating tags with fewer than three parts (`@v4`, `@v4.1`) are skipped:
#     they track the latest release of that line, so the resolved version is
#     unknown and comparing `4` against `<4.0.1` would be a false positive.
#   * Best-effort line matching: a literal `uses: owner/repo@ref` line buried
#     inside a `run:` shell block would be treated as a step reference. This
#     mirrors the line-oriented approach of the other lockfile parsers.
analyze_github_workflow() {
    local lockfile="$1"
    local eco="${2:-githubactions}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    {
        line = $0
        gsub(/\r/, "", line)                    # tolerate CRLF checkouts

        # Only lines whose key is `uses:` (optionally a `- uses:` list item).
        if (line !~ /^[[:space:]]*-?[[:space:]]*uses[[:space:]]*:/) next

        # Strip everything up to and including the `uses:` key.
        val = line
        sub(/^[[:space:]]*-?[[:space:]]*uses[[:space:]]*:[[:space:]]*/, "", val)

        # Strip a trailing YAML comment (whitespace + # to EOL). Action refs
        # never contain a literal " #"; SHA-pin version comments are discarded.
        sub(/[[:space:]]+#.*$/, "", val)

        # Trim surrounding whitespace.
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)

        # Strip one layer of surrounding quotes (double or single).
        if (length(val) >= 2) {
            first = substr(val, 1, 1)
            last  = substr(val, length(val), 1)
            if ((first == "\"" && last == "\"") || (first == "'\''" && last == "'\''")) {
                val = substr(val, 2, length(val) - 2)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            }
        }

        if (val == "") next

        # Skip local actions (./ or ../) and docker image references.
        if (val ~ /^\.\.?\//) next
        if (val ~ /^docker:\/\//) next

        # Need an @ref to resolve a version; split at the LAST @ (refs never
        # contain @, and this is robust to any future name oddities).
        at = 0
        for (i = length(val); i >= 1; i--) {
            if (substr(val, i, 1) == "@") { at = i; break }
        }
        if (at <= 1) next
        name = substr(val, 1, at - 1)
        ref  = substr(val, at + 1)
        if (name == "" || ref == "") next

        # A real action reference is owner/repo[/subpath] — require the slash.
        # This drops stray `uses:` lines that are not action references.
        if (index(name, "/") == 0) next

        # Canonical GitHub Actions name: lowercased owner/repo[/subpath].
        name = tolower(name)

        # Version tag: strip a leading `v` before a digit (v1.2.3 -> 1.2.3).
        # Branch names and 40-hex commit SHAs pass through unchanged.
        if (ref ~ /^v[0-9]/) sub(/^v/, "", ref)

        # Floating major/minor tags (@v4, @v4.1) move with every release: the
        # commit they resolve to is unknown here, so comparing "46" against
        # "<46.0.1" would flag every user of a long-patched action. Skip them.
        if (ref ~ /^[0-9]+(\.[0-9]+)?$/) next

        if (name != "" && ref != "") print name "|" ref
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
# ============================================================================
# Runtime version check (Node.js, PHP)
#
# A project also targets a runtime: .nvmrc, a Docker base image, the PHP
# version composer resolves for... Those versions are checked against the
# runtime feed (data/osv-runtime.purl, lines pkg:runtime/<node|php>@<range>,
# see fetch_runtime in src/60-feeds.sh).
#
#   * an exact version (22.1.0) is a normal finding: [runtime] node@22.1.0;
#   * a release line (20, 8.3, node:20-alpine) floats to its latest release:
#     it is reported only when no release of the line is fixed (EOL line);
#   * a range (>=18, ^8.1) is reported when its lowest admitted version is
#     vulnerable.
# Lines and ranges are yellow warnings only: they never change the exit code.
# Values that name no version (lts/*, latest, ${NODE_VERSION}) are ignored.
#
# Runtime files are discovered with the lockfiles (discover_project_files) but
# are not ecosystem registry rows: they select no GHSA/OSV feed.
# ============================================================================

# find -name patterns of the runtime version files (package.json and the
# GitHub Actions workflows are matched separately by discover_project_files).
RUNTIME_FILE_NAMES=(.nvmrc .node-version .tool-versions .php-version composer.json composer.lock 'Dockerfile*' '*.Dockerfile' '*.dockerfile')

# Warnings printed again in the summary (one line per file and runtime).
RUNTIME_WARNINGS=()

# A line any file naming a runtime version contains (a superset of what
# runtime_specs reads): most package.json files have no engines and must not
# pull the runtime feed.
RUNTIME_HINT_RE='"(engines|volta)"[[:space:]]*:|"php"[[:space:]]*:|"platform-overrides"|(node|php)-version[[:space:]]*:|^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]].*(node|php)|^(nodejs|node|php)[[:space:]]|^[[:space:]]*[vV]?[0-9]'

# Print the files of a newline-separated list that may name a runtime version
# (one grep for all of them).
runtime_files_with_versions() {
    [ -n "$1" ] || return 0
    printf '%s\n' "$1" | tr '\n' '\0' | xargs -0 grep -lE -- "$RUNTIME_HINT_RE" 2>/dev/null || true
}

# Classify a discovered file. Sets RUNTIME_KIND; returns 1 when the file names
# no runtime version.
runtime_file_kind() {
    local file="$1"
    case "${file##*/}" in
        .nvmrc|.node-version) RUNTIME_KIND=node_version ;;
        .php-version) RUNTIME_KIND=php_version ;;
        .tool-versions) RUNTIME_KIND=tool_versions ;;
        package.json) RUNTIME_KIND=package_json ;;
        composer.json) RUNTIME_KIND=composer_json ;;
        composer.lock) RUNTIME_KIND=composer_lock ;;
        Dockerfile*|*.Dockerfile|*.dockerfile) RUNTIME_KIND=dockerfile ;;
        *.yml|*.yaml)
            [[ "$file" == */.github/workflows/* ]] || return 1
            RUNTIME_KIND=workflow ;;
        *) return 1 ;;
    esac
}

# Print "runtime|spec" for every runtime version a file names, raw (quotes
# and comments removed).
runtime_specs() {
    local file="$1" content obj value
    runtime_file_kind "$file" || return 0
    case "$RUNTIME_KIND" in
        node_version|php_version)
            local rt=node
            [ "$RUNTIME_KIND" = node_version ] || rt=php
            awk -v rt="$rt" '{ sub(/\r$/, ""); sub(/#.*/, "") } NF { print rt "|" $1; exit }' "$file"
            ;;
        tool_versions)
            # asdf / mise: "nodejs 22.1.0 20.0.0" (every listed version is installed)
            awk '{ sub(/\r$/, ""); sub(/#.*/, "") }
                $1 == "nodejs" || $1 == "node" || $1 == "php" {
                    rt = ($1 == "php") ? "php" : "node"
                    for (i = 2; i <= NF; i++) print rt "|" $i
                }' "$file"
            ;;
        package_json)
            grep -qE '"(engines|volta)"[[:space:]]*:' "$file" || return 0
            content=$(cat "$file")
            for obj in engines volta; do
                value=$(json_get_value "$(json_get_object "$content" "$obj")" node)
                [ -z "$value" ] || [ "$value" = null ] || printf 'node|%s\n' "$value"
            done
            ;;
        composer_json)
            grep -q '"php"' "$file" || return 0
            content=$(cat "$file")
            # config.platform.php: the PHP version composer resolves for
            value=$(json_get_value "$(json_get_object "$(json_get_object "$content" config)" platform)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            value=$(json_get_value "$(json_get_object "$content" require)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            ;;
        composer_lock)
            grep -q '"platform-overrides"' "$file" || return 0
            value=$(json_get_value "$(json_get_object "$(cat "$file")" platform-overrides)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            ;;
        dockerfile)
            # FROM [--platform=...] [registry/][library/]node:TAG[@digest] [AS name]
            awk '{ sub(/\r$/, "") }
                toupper($1) == "FROM" {
                    i = 2
                    while (i <= NF && substr($i, 1, 2) == "--") i++
                    image = $i
                    sub(/@.*/, "", image)
                    colon = 0
                    for (j = length(image); j > 0; j--) {
                        c = substr(image, j, 1)
                        if (c == "/") break
                        if (c == ":") { colon = j; break }
                    }
                    if (colon == 0) next
                    name = tolower(substr(image, 1, colon - 1))
                    tag = substr(image, colon + 1)
                    sub(/^(index\.)?docker\.io\//, "", name)
                    sub(/^library\//, "", name)
                    if (name != "node" && name != "php") next
                    # Variant suffixes name no version: 20-alpine, 8.3.10-fpm-bookworm
                    if (match(tag, /^[vV]?[0-9]+(\.[0-9]+)*/) && (RLENGTH == length(tag) || substr(tag, RLENGTH + 1, 1) == "-"))
                        tag = substr(tag, 1, RLENGTH)
                    print name "|" tag
                }' "$file"
            ;;
        workflow)
            # node-version: 22.1.0 | [18, 20] | a block list; php-version: likewise
            awk '
            function emit(rt, v) {
                gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", v)
                if (v != "") print rt "|" v
            }
            { sub(/\r$/, "") }
            list_rt != "" {
                if (match($0, /^[[:space:]]*-[[:space:]]+/) && RLENGTH > list_indent) {
                    v = substr($0, RLENGTH + 1)
                    sub(/[[:space:]]+#.*/, "", v)
                    emit(list_rt, v)
                    next
                }
                if ($0 !~ /^[[:space:]]*(#.*)?$/) list_rt = ""
            }
            match($0, /^[[:space:]]*(-[[:space:]]+)?(node|php)-version:/) {
                key_indent = RLENGTH
                rt = ($0 ~ /php-version:/) ? "php" : "node"
                v = substr($0, RLENGTH + 1)
                sub(/[[:space:]]+#.*/, "", v)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                if (v == "") { list_rt = rt; list_indent = key_indent - length(rt "-version:"); next }
                if (substr(v, 1, 1) == "[") {
                    gsub(/[][]/, "", v)
                    n = split(v, items, ",")
                    for (k = 1; k <= n; k++) emit(rt, items[k])
                } else emit(rt, v)
            }' "$file"
            ;;
    esac
}

# Normalize a raw spec: no quotes or blanks at the ends, no "v" before a
# version, ".x" / ".*" wildcards dropped (20.x -> 20). Sets RT_SPEC.
runtime_normalize_spec() {
    local s="$1"
    s="${s#"${s%%[![:space:]\"\']*}"}"
    s="${s%"${s##*[![:space:]\"\']}"}"
    [[ "$s" == [vV][0-9]* ]] && s="${s:1}"
    while [[ "$s" == *.[xX*] ]]; do s="${s%.?}"; done
    RT_SPEC="$s"
}

# Lowest version a range admits, padded to x.y.z (>=18 -> 18.0.0,
# ^8.1 || ^7.4 -> 7.4.0). Alternatives without a lower bound (<20, *) are
# skipped. Sets RT_FLOOR (empty when no alternative has one).
runtime_range_floor() {
    local spec="${1//||/|}" alt token v
    local -a alts tokens parts
    RT_FLOOR=""
    IFS='|' read -ra alts <<< "$spec"
    for alt in "${alts[@]}"; do
        alt="${alt//,/ }"
        # Glue a detached operator to its version: ">= 18" -> ">=18"
        while [[ "$alt" =~ ^(.*)(\>=|\>|~\>|~=|\^|~|==|=)[[:space:]]+(.*)$ ]]; do
            alt="${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
        done
        read -ra tokens <<< "$alt"
        v=""
        for token in "${tokens[@]}"; do
            if [[ "$token" =~ ^(\>=|\>|~\>|~=|\^|~|==|=)?[vV]?([0-9]+(\.[0-9xX*]+)*)$ ]]; then
                v="${BASH_REMATCH[2]}"
                break
            fi
        done
        [ -n "$v" ] || continue
        while [[ "$v" == *.[xX*] ]]; do v="${v%.?}"; done
        IFS='.' read -ra parts <<< "$v"
        v="${parts[0]}.${parts[1]:-0}.${parts[2]:-0}"
        if [ -z "$RT_FLOOR" ]; then
            RT_FLOOR="$v"
        else
            compare_versions "$v" "$RT_FLOOR"
            [ "$COMPARE_RESULT" != -1 ] || RT_FLOOR="$v"
        fi
    done
}

# Integer key of a plain x.y.z version (missing parts count as 0), ordered
# like compare_versions for such versions. Sets RT_KEY; returns 1 for any
# other version (pre-release, 6+ digit minor or patch).
_rt_numeric_key() {
    [[ "$1" =~ ^[vV]?([0-9]{1,8})(\.([0-9]{1,5}))?(\.([0-9]{1,5}))?$ ]] || return 1
    RT_KEY=$(( 10#${BASH_REMATCH[1]} * 10000000000 + 10#${BASH_REMATCH[3]:-0} * 100000 + 10#${BASH_REMATCH[5]:-0} ))
}

# Per runtime, the loaded feed indexed once (runtime_index): RT_INDEX[rt]
# holds one "range|ident|fix_key|fix" row per advisory record, RT_COND
# ["rt|range"] the range as integer comparators ("op key op key", "*" or "!";
# empty when a bound is not plain x.y.z: version_in_range decides).
declare -A RT_INDEX=() RT_COND=() RT_AFFECTED_CACHE=()

runtime_index() {
    local rt="$1" key="runtime:$1" range rec recs rows="" cond parsed i ok
    local ghsa cve fix id ident fix_key
    local -a tokens
    while IFS= read -r range; do
        [ -n "$range" ] || continue
        cond=""
        case "$range" in
            # Alternatives and intervals: version_in_range decides.
            *"|"*|*"["*|*"("*) ;;
            *)
                [ -n "${RANGE_CACHE[runtime|$range]+x}" ] || _prepare_range "$range" "runtime|$range"
                parsed="${RANGE_CACHE[runtime|$range]}"
                case "$parsed" in
                    "*"|"!") cond="$parsed" ;;
                    *)
                        ok=true
                        read -ra tokens <<< "$parsed"
                        for (( i = 0; i < ${#tokens[@]}; i += 2 )); do
                            _rt_numeric_key "${tokens[i + 1]}" || { ok=false; break; }
                            cond+="${tokens[i]} $RT_KEY "
                        done
                        [ "$ok" = true ] || cond="" ;;
                esac ;;
        esac
        RT_COND["$rt|$range"]="${cond% }"
        recs="${VULN_RECORDS[$key:$range]:-}"
        while [ -n "$recs" ]; do
            # "severity;ghsa;cve;source;fix;id", split without a subshell
            rec="${recs%%$'\n'*}"
            recs="${recs#*$'\n'}"
            [ "$rec" != "$recs" ] || recs=""
            rec="${rec#*;}"; ghsa="${rec%%;*}"
            rec="${rec#*;}"; cve="${rec%%;*}"
            rec="${rec#*;}"; rec="${rec#*;}"; fix="${rec%%;*}"
            id="${rec#*;}"
            ident="${cve:-${ghsa:-$id}}"
            [ -n "$ident" ] || continue
            fix_key=""
            [ -z "$fix" ] || ! _rt_numeric_key "$fix" || fix_key="$RT_KEY"
            rows+="$range|$ident|$fix_key|$fix"$'\n'
        done
    done <<< "${VULN_RANGE_LOOKUP[$key]:-}"
    RT_INDEX["$rt"]="$rows"
}

# Advisories of a runtime that affect one version. Sets RT_IDS (sorted,
# space-separated CVE or advisory ids) and RT_FIX (for each advisory, the
# lowest fixed version above VERSION; the highest of those, so that one
# upgrade fixes them all). Returns 1 when no advisory affects VERSION.
# Results are cached per version: workflows repeat the same lines.
runtime_affected() {
    local rt="$1" version="$2" cached="$1|$2"
    if [ -n "${RT_AFFECTED_CACHE[$cached]+x}" ]; then
        cached="${RT_AFFECTED_CACHE[$cached]}"
        [ -n "$cached" ] || return 1
        RT_IDS="${cached%%|*}" RT_FIX="${cached#*|}"
        return 0
    fi
    [ -n "${RT_INDEX[$rt]+x}" ] || runtime_index "$rt"
    local key="runtime:$1" range ident fix_key fix cond vkey="" i matched candidate rec lk lf
    local severity ghsa cve source id
    local -A hit=() lowest_key=() lowest_fix=() range_hit=()
    local -a c exacts
    RT_IDS="" RT_FIX=""
    CHECK_ECO=runtime
    ! _rt_numeric_key "$version" || vkey="$RT_KEY"
    while IFS='|' read -r range ident fix_key fix; do
        [ -n "$range" ] || continue
        if [ -z "${range_hit[$range]+x}" ]; then
            cond="${RT_COND[$rt|$range]}"
            matched=0
            if [ -n "$vkey" ] && [ -n "$cond" ]; then
                case "$cond" in
                    "*") matched=1 ;;
                    "!") ;;
                    *)
                        matched=1
                        read -ra c <<< "$cond"
                        for (( i = 0; i < ${#c[@]}; i += 2 )); do
                            case "${c[i]}" in
                                ">=") (( vkey >= c[i + 1] )) ;;
                                ">") (( vkey > c[i + 1] )) ;;
                                "<") (( vkey < c[i + 1] )) ;;
                                "<=") (( vkey <= c[i + 1] )) ;;
                                "=") (( vkey == c[i + 1] )) ;;
                                "!=") (( vkey != c[i + 1] )) ;;
                            esac || { matched=0; break; }
                        done ;;
                esac
            elif version_in_range "$version" "$range"; then
                matched=1
            fi
            range_hit["$range"]=$matched
        fi
        [ "${range_hit[$range]}" = 0 ] || hit["$ident"]=1
        [ -n "$fix" ] || continue
        # Lowest fix above VERSION, per advisory (integer keys when both
        # sides are plain x.y.z, compare_versions otherwise).
        lk="${lowest_key[$ident]:-}" lf="${lowest_fix[$ident]:-}"
        if [ -n "$vkey" ] && [ -n "$fix_key" ]; then
            (( fix_key > vkey )) || continue
            if [ -n "$lk" ]; then
                (( fix_key < lk )) || continue
            elif [ -n "$lf" ]; then
                compare_versions "$fix" "$lf"
                [ "$COMPARE_RESULT" = -1 ] || continue
            fi
        else
            compare_versions "$fix" "$version"
            [ "$COMPARE_RESULT" = 1 ] || continue
            if [ -n "$lf" ]; then
                compare_versions "$fix" "$lf"
                [ "$COMPARE_RESULT" = -1 ] || continue
            fi
        fi
        lowest_key["$ident"]="$fix_key"
        lowest_fix["$ident"]="$fix"
    done <<< "${RT_INDEX[$rt]}"
    IFS='|' read -ra exacts <<< "${VULN_EXACT_LOOKUP[$key]:-}"
    for candidate in "${exacts[@]}"; do
        [ -n "$candidate" ] && version_matches_vulnerable "$version" "$candidate" || continue
        while IFS= read -r rec; do
            IFS=';' read -r severity ghsa cve source fix id <<< "$rec"
            ident="${cve:-${ghsa:-$id}}"
            [ -z "$ident" ] || hit["$ident"]=1
        done <<< "${VULN_RECORDS[$key@$candidate]:-}"
    done
    if [ ${#hit[@]} -eq 0 ]; then
        RT_AFFECTED_CACHE["$rt|$version"]=""
        return 1
    fi
    RT_IDS=$(printf '%s\n' "${!hit[@]}" | sort | tr '\n' ' ')
    RT_IDS="${RT_IDS% }"
    for ident in "${!hit[@]}"; do
        fix="${lowest_fix[$ident]:-}"
        [ -n "$fix" ] || continue
        if [ -n "$RT_FIX" ]; then
            compare_versions "$fix" "$RT_FIX"
            [ "$COMPARE_RESULT" = 1 ] || continue
        fi
        RT_FIX="$fix"
    done
    RT_AFFECTED_CACHE["$rt|$version"]="$RT_IDS|$RT_FIX"
    return 0
}

runtime_display_name() {
    case "$1" in
        node) echo "Node.js" ;;
        php) echo "PHP" ;;
        *) echo "$1" ;;
    esac
}

# Check the runtime versions of every RUNTIME_FILES entry (see the header).
scan_runtimes() {
    local file rt spec probe kind count before=${#VULNERABLE_PACKAGES[@]} warned=0
    local -A seen=() warn_specs=() warn_ids=() warn_fix=() warn_kind=()
    local ids n message label
    count=$(printf '%s\n' "$RUNTIME_FILES" | wc -l | tr -d ' ')
    echo "🧩 Checking runtime versions in $count file(s)..."
    while IFS= read -r file; do
        # Unreadable files never get here (runtime_files_with_versions).
        [ -n "$file" ] || continue
        # Per runtime: the specs to warn about, their advisories, the fix.
        warn_specs=() warn_ids=() warn_fix=() warn_kind=()
        while IFS='|' read -r rt spec; do
            [ -n "$rt" ] || continue
            runtime_normalize_spec "$spec"
            spec="$RT_SPEC"
            [ -z "${seen[$file|$rt|$spec]+x}" ] || continue
            seen["$file|$rt|$spec"]=1
            if [[ "$spec" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                check_vulnerability "runtime" "$rt" "$spec" "$file" || true
                continue
            fi
            # Warnings belong to full scans, not to a --package-name lookup.
            [ -z "${PACKAGE_FILTER:-}" ] || continue
            if [[ "$spec" =~ ^[0-9]+$ ]]; then
                probe="$spec.99999.99999" kind=line
            elif [[ "$spec" =~ ^[0-9]+\.[0-9]+$ ]]; then
                probe="$spec.99999" kind=line
            elif [[ "$spec" =~ [\<\>=^~|,*\ ] ]]; then
                runtime_range_floor "$spec"
                [ -n "$RT_FLOOR" ] || continue
                probe="$RT_FLOOR" kind=range
            else
                continue
            fi
            runtime_affected "$rt" "$probe" || continue
            warn_specs["$rt"]+="${warn_specs[$rt]:+, }$spec"
            warn_ids["$rt"]+="${warn_ids[$rt]:+ }$RT_IDS"
            [ "$kind" = line ] && [ -n "${warn_kind[$rt]:-}" ] || warn_kind["$rt"]="$kind"
            if [ -n "$RT_FIX" ]; then
                if [ -z "${warn_fix[$rt]:-}" ]; then
                    warn_fix["$rt"]="$RT_FIX"
                else
                    compare_versions "$RT_FIX" "${warn_fix[$rt]}"
                    [ "$COMPARE_RESULT" != 1 ] || warn_fix["$rt"]="$RT_FIX"
                fi
            fi
        done < <(runtime_specs "$file")

        for rt in "${!warn_specs[@]}"; do
            # Newest advisories first (CVE-YYYY-NNNN).
            # shellcheck disable=SC2086 # space-separated advisory ids
            ids=$(printf '%s\n' ${warn_ids[$rt]} | sort -u | sort -t- -k2,2nr -k3,3nr)
            n=$(printf '%s\n' "$ids" | wc -l | tr -d ' ')
            ids=$(printf '%s\n' "$ids" | head -n 3 | tr '\n' ' ')
            ids="${ids% }"
            ids="${ids// /, }"
            [ "$n" -le 3 ] || ids+=" (+$((n - 3)) more)"
            label="$(runtime_display_name "$rt") ${warn_specs[$rt]}"
            if [ "${warn_kind[$rt]}" = line ]; then
                message="$label: no release of this line fixes $ids"
                [ -z "${warn_fix[$rt]:-}" ] || message+="; move to >= ${warn_fix[$rt]}"
            else
                message="$label allows vulnerable versions ($ids)"
                [ -z "${warn_fix[$rt]:-}" ] || message+="; raise the minimum to >= ${warn_fix[$rt]}"
            fi
            echo -e "${YELLOW}⚠️  [$file] $message${NC}"
            RUNTIME_WARNINGS+=("[$file] $message")
            warned=$((warned + 1))
        done
    done <<< "$RUNTIME_FILES"

    if [ "${#VULNERABLE_PACKAGES[@]}" -eq "$before" ] && [ "$warned" -eq 0 ]; then
        echo -e "${GREEN}✓ Runtime versions: no known vulnerability${NC}"
    fi
}
# Write a JSON string without a subshell or a runtime JSON dependency.
json_print_string() {
    local value="$1" code char escaped
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    if [[ "$value" == *[$'\001'-$'\037']* ]]; then
        for ((code = 1; code < 32; code++)); do
            printf -v escaped '\\%03o' "$code"
            printf -v char '%b' "$escaped"
            printf -v escaped '\\u%04x' "$code"
            value="${value//"$char"/"$escaped"}"
        done
    fi
    printf '"%s"' "$value"
}

# Summary metadata of one finding: the most severe advisory's fields, the
# version that fixes every advisory (see finalize_advisories) and, with
# --go-reachability, whether the code calls it.
export_metadata() {
    local eco="$1" pkg="$2" file="$3"
    local key="${eco}:${pkg}" name="${pkg%@*}"
    severity="${VULN_METADATA_SEVERITY[$key]:-${VULN_METADATA_SEVERITY[$name]:-}}"
    ghsa="${VULN_METADATA_GHSA[$key]:-${VULN_METADATA_GHSA[$name]:-}}"
    cve="${VULN_METADATA_CVE[$key]:-${VULN_METADATA_CVE[$name]:-}}"
    source="${VULN_METADATA_SOURCE[$key]:-${VULN_METADATA_SOURCE[$name]:-}}"
    fixed_in="${VULN_METADATA_FIX[$key]:-}"
    reachability_of "$file" "$key"
    reachability="$REACHABILITY"
}

# The report is written even when nothing is vulnerable, so a CI job never
# picks up a stale report from an earlier run.
export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"
    local vuln file eco pkg severity ghsa cve source fixed_in reachability field first=true
    local advisories advisory a_first a_sev a_ghsa a_cve a_source a_fix a_id
    local -A unique=()
    {
        printf '{\n  "vulnerabilities": ['
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            unique["${eco}:${pkg}"]=1
            if [ "$first" = true ]; then first=false; printf '\n'; else printf ',\n'; fi
            export_metadata "$eco" "$pkg" "$file"
            printf '    {"package": '; json_print_string "$pkg"
            printf ', "name": '; json_print_string "${pkg%@*}"
            printf ', "version": '; json_print_string "${pkg##*@}"
            printf ', "file": '; json_print_string "$file"
            printf ', "ecosystem": '; json_print_string "$eco"
            for field in severity ghsa cve source fixed_in reachability; do
                if [ -n "${!field}" ]; then
                    printf ', "%s": ' "$field"
                    json_print_string "${!field}"
                fi
            done
            printf ', "advisories": ['
            advisories="${VULN_ADVISORIES[$eco:$pkg]:-}"
            a_first=true
            while [ -n "$advisories" ]; do
                advisory="${advisories%%||*}"
                if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
                IFS=';' read -r a_sev a_ghsa a_cve a_source a_fix a_id <<< "$advisory"
                [ -n "$a_sev$a_ghsa$a_cve$a_source$a_fix$a_id" ] || continue
                if [ "$a_first" = true ]; then a_first=false; else printf ', '; fi
                printf '{"severity": '; json_print_string "$a_sev"
                printf ', "ghsa": '; json_print_string "$a_ghsa"
                printf ', "cve": '; json_print_string "$a_cve"
                printf ', "id": '; json_print_string "$a_id"
                printf ', "source": '; json_print_string "$a_source"
                printf ', "fix": '; json_print_string "$a_fix"
                printf '}'
            done
            printf ']}'
        done
        [ "$first" = true ] || printf '\n  '
        printf '],\n  "summary": {\n'
        printf '    "total_unique_vulnerabilities": %s,\n' "${#unique[@]}"
        printf '    "total_occurrences": %s\n' "${#VULNERABLE_PACKAGES[@]}"
        printf '  }\n}\n'
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

# Quote one CSV cell. A cell starting with = + - @ (or a tab/CR) is a formula
# in spreadsheet applications: prefix it with an apostrophe.
csv_cell() {
    local value="$1"
    case "$value" in
        [=+@-]*|$'\t'*|$'\r'*) value="'$value" ;;
    esac
    printf '"%s"' "${value//\"/\"\"}"
}

export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"
    local vuln file eco pkg severity ghsa cve source fixed_in reachability value first
    {
        printf 'package,file,severity,ghsa,cve,source,ecosystem,version,fix,reachability\n'
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"
            export_metadata "$eco" "$pkg" "$file"
            first=true
            for value in "$pkg" "$file" "$severity" "$ghsa" "$cve" "$source" "$eco" "${pkg##*@}" "$fixed_in" "$reachability"; do
                if [ "$first" = true ]; then first=false; else printf ','; fi
                csv_cell "$value"
            done
            printf '\n'
        done
    } > "$output_file" || return 1
    echo -e "${GREEN}✓ CSV report exported to: $output_file${NC}"
}
# ============================================================================
# Vulnerability Feed Generation Functions
# ============================================================================
#
# Feeds are generated from two upstream sources, both using the OSV schema:
#   - GHSA:  a single sparse clone of github/advisory-database, scanned once,
#            emitting PURL lines for every supported ecosystem at once.
#   - OSV:   one all.zip per ecosystem from the OSV GCS bucket.
#   - Runtime: the Node.js / PHP advisories of the OSV "Bitnami" ecosystem
#            (fetch_runtime), checked against the runtime a project targets.
#
# jq is REQUIRED here (fetch path only); the scan path stays jq-free.
#
# FEED_ECOSYSTEM_MAP is the single source of truth mapping:
#   purl-type | OSV/GHSA ecosystem string | OSV zip directory (URL-encoded)
#
# The "ecosystem string" is matched against .affected[].package.ecosystem in the
# advisory JSON; the "zip directory" is the path segment used to fetch
# https://osv-vulnerabilities.storage.googleapis.com/<dir>/all.zip .
#
# Empirically verified (HEAD requests to the OSV bucket + ecosystems.txt index +
# real advisory JSON): all 12 directories return 200 and the ecosystem strings
# below match the upstream data exactly (notably "SwiftURL" and "GitHub Actions").
# ============================================================================
FEED_ECOSYSTEM_MAP=(
    "npm|npm|npm"
    "pypi|PyPI|PyPI"
    "golang|Go|Go"
    "maven|Maven|Maven"
    "cargo|crates.io|crates.io"
    "gem|RubyGems|RubyGems"
    "composer|Packagist|Packagist"
    "nuget|NuGet|NuGet"
    "pub|Pub|Pub"
    "hex|Hex|Hex"
    "swift|SwiftURL|SwiftURL"
    "githubactions|GitHub Actions|GitHub%20Actions"
)

# Space-separated list of every supported purl type, in table order.
feed_all_types() {
    local entry types=""
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        types="${types:+$types }${entry%%|*}"
    done
    printf '%s' "$types"
}

# Print the OSV/GHSA ecosystem string for a purl type (empty if unsupported).
feed_eco_string() {
    local type="$1" entry t eco dir
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        IFS='|' read -r t eco dir <<< "$entry"
        if [ "$t" = "$type" ]; then printf '%s' "$eco"; return 0; fi
    done
    return 0
}

# Print the OSV zip directory (URL-encoded) for a purl type.
feed_osv_dir() {
    local type="$1" entry t eco dir
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        IFS='|' read -r t eco dir <<< "$entry"
        if [ "$t" = "$type" ]; then printf '%s' "$dir"; return 0; fi
    done
    return 0
}

# Build a JSON object mapping {ecosystem-string: purl-type} for the given purl
# types, consumed by the shared jq program via --argjson. Ecosystem strings are
# simple ASCII (no quotes/backslashes) so hand-building the JSON is safe.
feed_build_ecomap() {
    local out="{" first=1 t eco
    for t in "$@"; do
        [ -z "$t" ] && continue
        eco=$(feed_eco_string "$t")
        [ -z "$eco" ] && continue
        [ "$first" -eq 0 ] && out="$out,"
        out="$out\"$eco\":\"$t\""
        first=0
    done
    printf '%s}' "$out"
}

# Shared jq program. Emits one PURL line per affected package/range for every
# ecosystem present in $ecomap. Reproduces the legacy npm emission byte-for-byte
# (npm's transform is identity and $ecomap={"npm":"npm"} matches the old filter),
# while adding per-type name canonicalization that MUST match canon_purl_name in
# the scan-side parser (src/31-parsers-purl.sh):
#   pypi           -> lowercase, collapse runs of [-_.] to a single '-'
#   maven          -> groupId:artifactId emitted as groupId/artifactId
#   composer/nuget -> lowercase
#   githubactions  -> strip any scheme and "github.com/", lowercase
#   swift          -> strip any scheme, trailing "/" and ".git", lowercase
#   npm/golang/cargo/gem/pub/hex -> name as-is
# $source is "ghsa" or "osv" (the source= param). Severity: the advisory's own
# (GHSA database_specific), else the CVSS 3.x base score computed from the
# first CVSS_V3 vector, MAL- (malicious package) advisories being critical.
FEED_JQ_PROGRAM='
def emit_name($type; $name):
    if $type == "pypi" then ($name | ascii_downcase | gsub("[-_.]+"; "-"))
    elif $type == "maven" then ($name | gsub(":"; "/"))
    elif ($type == "composer" or $type == "nuget") then ($name | ascii_downcase)
    elif $type == "githubactions" then ($name | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | sub("^github\\.com/"; "") | sub("/+$"; "") | ascii_downcase)
    elif $type == "swift" then ($name | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | sub("/+$"; "") | sub("\\.git$"; "") | ascii_downcase)
    else $name end;

# CVSS 3.x base score of a vector ("CVSS:3.1/AV:N/AC:L/..."), null when the
# vector is not a complete 3.x one. Roundup as defined by CVSS 3.1.
def roundup: ((. * 100000) | round) as $i
    | if ($i % 10000) == 0 then $i / 100000 else (($i / 10000 | floor) + 1) / 10 end;
def cvss3_score:
    if (type == "string" and test("^CVSS:3\\.[01]/")) then
        # A missing metric reads as "" so the lookups give null, never an error.
        ((split("/")[1:] | map(split(":") | {(.[0]): (.[1] // "")}) | add) // {}) as $m
        | ($m.S == "C") as $changed
        | ({"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[$m.AV // ""]) as $av
        | ({"L": 0.77, "H": 0.44}[$m.AC // ""]) as $ac
        | (if $changed then {"N": 0.85, "L": 0.68, "H": 0.5} else {"N": 0.85, "L": 0.62, "H": 0.27} end)[$m.PR // ""] as $pr
        | ({"N": 0.85, "R": 0.62}[$m.UI // ""]) as $ui
        | ([$m.C, $m.I, $m.A] | map({"H": 0.56, "L": 0.22, "N": 0}[. // ""])) as $cia
        | if ([$av, $ac, $pr, $ui] + $cia | any(. == null)) then null else
            (1 - ((1 - $cia[0]) * (1 - $cia[1]) * (1 - $cia[2]))) as $iss
            | (if $changed then 7.52 * ($iss - 0.029) - 3.25 * pow($iss - 0.02; 15) else 6.42 * $iss end) as $impact
            | (8.22 * $av * $ac * $pr * $ui) as $exploit
            | if $impact <= 0 then 0
              elif $changed then ([1.08 * ($impact + $exploit), 10] | min | roundup)
              else ([$impact + $exploit, 10] | min | roundup) end
          end
    elif (type == "string" and test("^[0-9]+(\\.[0-9]+)?$")) then tonumber
    else null end;
def score_severity:
    if . >= 9.0 then "CRITICAL"
    elif . >= 7.0 then "HIGH"
    elif . >= 4.0 then "MODERATE"
    elif . > 0 then "LOW"
    else null end;

select(.withdrawn == null) |
.id as $id |
(if ($id | startswith("MAL-")) then "CRITICAL"
 else (.database_specific.severity //
       first(.severity[]? | select(.type == "CVSS_V3") | .score | cvss3_score | numbers | score_severity | strings) //
       "UNKNOWN") end) as $severity |

(.aliases // []) as $aliases |
# The GHSA id is the advisory id itself (GHSA feed, and OSV copies of GHSA
# advisories) or else a GHSA alias. Any other non-CVE id (PYSEC-, GO-,
# RUSTSEC-, MAL-, ...) is kept as id=.
(if ($id | startswith("GHSA-")) then $id
 else ($aliases | map(select(startswith("GHSA-"))) | .[0] // "") end) as $ghsa |
(if ($id | startswith("CVE-")) then $id
 else ($aliases | map(select(startswith("CVE-"))) | .[0] // "") end) as $cve |
(if ($id | startswith("GHSA-") or startswith("CVE-")) then "" else $id end) as $other_id |
([
    ("severity=" + ($severity | ascii_downcase)),
    (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
    (if $cve != "" then "cve=" + $cve else empty end),
    (if $other_id != "" then "id=" + $other_id else empty end),
    ("source=" + $source)
] | join("&")) as $params |

.affected[]? |
.package.ecosystem as $e |
($ecomap[$e // ""] // "") as $type |
select($type != "") |
(emit_name($type; .package.name)) as $pkg |
# GHSA records the upper bound of an interval with no known fix here
# ("< 3.0.0", "<= 2.26.11"): it bounds the open interval, but is no fix.
((.database_specific.last_known_affected_version_range // "") | gsub(" "; "")
 | if test("^<=?[0-9A-Za-z]") then . else "" end) as $last_known |
(
    (.ranges[]? |
        select(.type == "SEMVER" or .type == "ECOSYSTEM") |
        .events |
        ([.[] | select(.limit) | .limit] | if length == 0 then ["*"] else . end) as $limits |
        map(select(.introduced or .fixed or .last_affected)) |
        if length > 0 then
            reduce .[] as $event (
                {current: {}, intervals: []};
                if $event.introduced then
                    .current = {introduced: $event.introduced}
                elif $event.fixed then
                    .intervals += [(.current + {fixed: $event.fixed})] |
                    .current = {}
                elif $event.last_affected then
                    .intervals += [(.current + {last_affected: $event.last_affected})] |
                    .current = {}
                else . end
            ) |
            (.intervals + (if .current.introduced then [.current] else [] end))[] |
            . as $interval |
            ($interval.fixed == null and $interval.last_affected == null and $last_known != "") as $bounded |
            ([
                (if .introduced then ">=" + .introduced else empty end),
                (if .fixed then "<" + .fixed else empty end),
                (if .last_affected then "<=" + .last_affected else empty end),
                (if $bounded then $last_known else empty end)
            ] | join(" ")) as $bounds |
            $limits[] as $limit |
            (if $limit == "*" then "" else " <" + $limit end) as $cap |
            # A limit or a last-known bound is an applicability boundary, not a
            # known patched version.
            (if ($limit != "*" or $bounded) and ($interval.fixed == null) then "&fixed=" else "" end) as $fix_override |
            "pkg:\($type)/\($pkg)@\($bounds)\($cap)?\($params)\($fix_override)"
        else empty end
    ),
    # Exact versions only for entries without SEMVER/ECOSYSTEM ranges (e.g. MAL
    # advisories): OSV enumerates every version a range covers, so emitting them
    # alongside ranges is redundant and pushes feeds past the GitHub 100 MB file limit.
    (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
        .versions[]? |
        "pkg:\($type)/\($pkg)@\(.)?\($params)"
    else empty end)
)'

# Run FEED_JQ_PROGRAM over every *.json file under an input directory, in
# parallel, and append the raw (unsorted) PURL lines to a combined file.
#   $1 input dir   $2 source ("ghsa"|"osv")   $3 ecomap JSON   $4 combined out
#
# Robustness: 8 parallel workers each write to their OWN temp file — never a
# shared pipe — because concurrent jq processes writing to one pipe interleave
# non-atomically and tear PURL lines (observed frequently under load). Each
# worker runs jq once per file, so a malformed advisory is isolated: it is
# skipped and counted (its partial output discarded) instead of failing the
# whole ecosystem. Only a failed worker, or every file failing, prevents
# replacement of the existing feed. Callers sort/split the combined file
# (LC_ALL=C for locale stability).
feed_emit_raw() {
    local in_dir="$1" src="$2" ecomap="$3" combined="$4"
    [ -d "$in_dir" ] && command -v jq >/dev/null 2>&1 || return 1
    local parts_dir total skipped
    parts_dir=$(mktemp -d)
    export FEED_JQ_PROGRAM
    if ! (set -o pipefail; find "$in_dir" -name "*.json" -type f -print0 | \
        FEED_SRC="$src" FEED_ECOMAP="$ecomap" PARTS_DIR="$parts_dir" \
        xargs -0 -P 8 -n 400 sh -c '
            out=$(mktemp "$PARTS_DIR/part.XXXXXX") || exit 1
            bad=$(mktemp "$PARTS_DIR/bad.XXXXXX") || exit 1
            for f in "$@"; do
                if lines=$(jq -r --arg source "$FEED_SRC" --argjson ecomap "$FEED_ECOMAP" "$FEED_JQ_PROGRAM" "$f" 2>/dev/null); then
                    [ -z "$lines" ] || printf "%s\n" "$lines"
                else
                    printf "%s\n" "$f" >> "$bad"
                fi
            done > "$out"
        ' _ 2>/dev/null); then
        echo "Error: Failed to generate feed; previous output preserved" >&2
        rm -rf "$parts_dir"
        return 1
    fi
    total=$(find "$in_dir" -name "*.json" -type f | wc -l | tr -d ' ')
    skipped=$(cat "$parts_dir"/bad.* 2>/dev/null | wc -l | tr -d ' ')
    if [ "$skipped" -gt 0 ]; then
        echo "⚠️  Skipped $skipped of $total advisory file(s) that jq could not process" >&2
        if [ "$skipped" -ge "$total" ]; then
            echo "Error: no advisory could be processed; previous output preserved" >&2
            rm -rf "$parts_dir"
            return 1
        fi
    fi
    cat "$parts_dir"/part.* > "$combined" 2>/dev/null || true
    rm -rf "$parts_dir"
}

# Fetch GitHub Security Advisory data for the requested ecosystems.
# Usage: fetch_ghsa [purl-type ...]   (default: all supported types)
# Writes data/ghsa.purl (npm, legacy name) and data/ghsa-<type>.purl (others)
# into ${FEED_OUTPUT_DIR:-data}. Performs a SINGLE sparse clone and a SINGLE
# parallel jq pass over the advisory files, then splits the combined output by
# pkg:<type>/ prefix — never cloning or scanning per ecosystem.
fetch_ghsa() {
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
    local -a types=("$@")
    if [ "${#types[@]}" -eq 0 ]; then
        read -ra types <<< "$(feed_all_types)"
    fi

    local out_dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)

    # Keep only supported types (warn + drop unknowns).
    local -a valid_types=()
    local t
    for t in "${types[@]}"; do
        [ -z "$t" ] && continue
        if [ -z "$(feed_eco_string "$t")" ]; then
            echo "⚠️  Skipping unknown ecosystem: $t" >&2
            continue
        fi
        valid_types+=("$t")
    done
    [ "${#valid_types[@]}" -eq 0 ] && return 0

    local ecomap
    ecomap=$(feed_build_ecomap "${valid_types[@]}")

    local ghsa_tmp
    ghsa_tmp=$(mktemp -d)
    local GHSA_REPO="https://github.com/github/advisory-database.git"
    local CLONE_DIR="$ghsa_tmp/advisory-database"

    echo "Cloning GitHub Advisory Database (all reviewed advisories)..." >&2

    # Shallow clone with sparse checkout for all reviewed advisories
    if ! git clone --filter=blob:none --no-checkout --depth 1 "$GHSA_REPO" "$CLONE_DIR" > "$ghsa_tmp/clone.log" 2>&1 || ! (
        cd "$CLONE_DIR" || exit 1
        git sparse-checkout init --cone &&
        git sparse-checkout set advisories/github-reviewed &&
        git checkout
    ) > "$ghsa_tmp/checkout.log" 2>&1; then
        echo "Error: Failed to fetch GHSA database; previous feeds preserved" >&2
        rm -rf "$ghsa_tmp"
        return 1
    fi

    echo "Processing GHSA advisories for: ${valid_types[*]}" >&2

    local file_count
    file_count=$(find "$CLONE_DIR/advisories/github-reviewed" -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count advisory files" >&2
    echo "Using parallel processing (single pass, all ecosystems)..." >&2

    # SINGLE parallel jq pass emitting PURLs for every requested ecosystem.
    local combined="$ghsa_tmp/combined.purl"
    if ! feed_emit_raw "$CLONE_DIR/advisories/github-reviewed" "ghsa" "$ecomap" "$combined"; then
        rm -rf "$ghsa_tmp"
        return 1
    fi

    # Split combined output by pkg:<type>/ prefix into per-ecosystem files.
    local base out_file line_count
    for t in "${valid_types[@]}"; do
        base=$(default_feed_filename "ghsa" "$t")
        out_file="$out_dir/$base"
        # LC_ALL=C: deterministic byte-order sort, reproducible across locales
        # (matches the CI runner and keeps committed feed diffs to real churn).
        local staged
        staged=$(mktemp "$out_file.tmp.XXXXXX") || return 1
        if ! { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u > "$staged" || ! mv "$staged" "$out_file"; then
            rm -f "$staged"
            rm -rf "$ghsa_tmp"
            return 1
        fi
        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2
    done

    rm -rf "$ghsa_tmp"
    echo "GHSA processing complete" >&2
}

# Fetch OSV vulnerability data for the requested ecosystems.
# Usage: fetch_osv [purl-type ...]   (default: all supported types)
# Writes data/osv.purl (npm, legacy name) and data/osv-<type>.purl (others)
# into ${FEED_OUTPUT_DIR:-data}. Downloads one all.zip per ecosystem and reuses
# the shared jq emission via the existing xargs -P 8 parallel pattern.
fetch_osv() {
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
    local failed=0
    local -a types=("$@")
    if [ "${#types[@]}" -eq 0 ]; then
        read -ra types <<< "$(feed_all_types)"
    fi

    local out_dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)

    local t eco_string osv_dir ecomap zip_file eco_tmp out_file base file_count line_count
    for t in "${types[@]}"; do
        [ -z "$t" ] && continue
        eco_string=$(feed_eco_string "$t")
        if [ -z "$eco_string" ]; then
            echo "⚠️  Skipping unknown ecosystem: $t" >&2
            continue
        fi
        osv_dir=$(feed_osv_dir "$t")
        ecomap=$(feed_build_ecomap "$t")
        base=$(default_feed_filename "osv" "$t")
        out_file="$out_dir/$base"

        eco_tmp=$(mktemp -d)
        zip_file="$eco_tmp/all.zip"

        echo "Fetching OSV $eco_string vulnerabilities..." >&2
        if ! curl -fsSL --connect-timeout 10 --max-time 300 "https://osv-vulnerabilities.storage.googleapis.com/${osv_dir}/all.zip" -o "$zip_file"; then
            echo "⚠️  Failed to download OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        echo "Extracting $eco_string vulnerabilities..." >&2
        if ! unzip -q "$zip_file" -d "$eco_tmp" 2>/dev/null; then
            echo "⚠️  Failed to extract OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        file_count=$(find "$eco_tmp" -name "*.json" -type f | wc -l | tr -d ' ')
        echo "Processing $file_count $eco_string files (parallel)..." >&2

        # Robust parallel emission, then deterministic C-locale sort/dedupe.
        local combined="$eco_tmp/combined.purl"
        local staged
        if ! feed_emit_raw "$eco_tmp" "osv" "$ecomap" "$combined"; then
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi
        staged=$(mktemp "$out_file.tmp.XXXXXX") || return 1
        if ! LC_ALL=C sort -u "$combined" > "$staged" || ! mv "$staged" "$out_file"; then
            rm -f "$staged"
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2

        rm -rf "$eco_tmp"
    done

    echo "OSV processing complete" >&2
    return "$failed"
}

# Runtimes whose own advisories are tracked (purl type "runtime"). The names
# are Bitnami package names; add one here to cover another runtime.
RUNTIME_FEED_PACKAGES="node php"

# Fetch runtime advisories (Node.js, PHP, ...) from the OSV Bitnami ecosystem,
# which carries the upstream version ranges of each runtime CVE.
# Writes ${FEED_OUTPUT_DIR:-data}/osv-runtime.purl (pkg:runtime/<name>@<range>).
# Only BIT-<name>-<year>-* advisories are extracted: the BIT-<name>-min-*
# copies describe the same CVEs for Bitnami's minimal images.
fetch_runtime() {
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
    local out_dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)

    local out_file="$out_dir/osv-runtime.purl" tmp pkg names="" staged line_count
    local -a patterns=()
    for pkg in $RUNTIME_FEED_PACKAGES; do
        patterns+=("BIT-$pkg-[0-9]*")
        names="${names:+$names|}$pkg"
    done
    tmp=$(mktemp -d)

    echo "Fetching OSV Bitnami runtime vulnerabilities ($RUNTIME_FEED_PACKAGES)..." >&2
    if ! curl -fsSL --connect-timeout 10 --max-time 300 "https://osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip" -o "$tmp/all.zip"; then
        echo "⚠️  Failed to download the OSV Bitnami feed; previous runtime feed preserved" >&2
        rm -rf "$tmp"
        return 1
    fi
    mkdir "$tmp/advisories"
    if ! unzip -q "$tmp/all.zip" "${patterns[@]}" -d "$tmp/advisories" 2>/dev/null; then
        echo "⚠️  Failed to extract the runtime advisories; previous runtime feed preserved" >&2
        rm -rf "$tmp"
        return 1
    fi

    if ! feed_emit_raw "$tmp/advisories" "osv" '{"Bitnami":"runtime"}' "$tmp/combined.purl"; then
        rm -rf "$tmp"
        return 1
    fi
    staged=$(mktemp "$out_file.tmp.XXXXXX") || { rm -rf "$tmp"; return 1; }
    # Other Bitnami packages listed in the same advisories are dropped.
    if ! { grep -E "^pkg:runtime/($names)@" "$tmp/combined.purl" || true; } | LC_ALL=C sort -u > "$staged" ||
        [ ! -s "$staged" ] || ! mv "$staged" "$out_file"; then
        echo "⚠️  No runtime advisory could be generated; previous runtime feed preserved" >&2
        rm -f "$staged"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    line_count=$(wc -l < "$out_file" | tr -d ' ')
    echo "  → osv-runtime.purl: $line_count entries" >&2
}

# Main orchestration function to fetch all PURL vulnerability feeds
# (GHSA + OSV) for every supported ecosystem.
fetch_all() {
    local output_dir="${1:-data}"

    echo "========================================="
    echo "Vulnerability PURL Feed Generator"
    echo "========================================="
    echo ""

    mkdir -p "$output_dir"

    export FEED_OUTPUT_DIR="$output_dir"

    # An OSV failure must not prevent the GHSA feeds: run both, report both.
    local status=0

    # Generate OSV feeds (one zip per ecosystem)
    echo "Generating OSV feeds for all ecosystems..."
    fetch_osv || status=1
    echo ""

    # Generate GHSA feeds (single clone, single pass, split per ecosystem)
    echo "Generating GHSA feeds for all ecosystems..."
    fetch_ghsa || status=1
    echo ""

    # Generate the runtime feed (Node.js, PHP: OSV Bitnami advisories)
    echo "Generating the runtime feed..."
    fetch_runtime || status=1
    echo ""

    unset FEED_OUTPUT_DIR

    echo "========================================="
    echo "Feed generation complete!"
    echo "========================================="
    echo "Per-ecosystem totals:"
    local f count total=0
    for f in "$output_dir"/*.purl; do
        [ -e "$f" ] || continue
        count=$(wc -l < "$f" | tr -d ' ')
        total=$((total + count))
        printf '  - %-24s %s\n' "$(basename "$f")" "$count"
    done
    echo "  ---------------------------------------"
    printf '  - %-24s %s\n' "TOTAL" "$total"
    echo ""
    [ "$status" -eq 0 ] || echo "⚠️  Some feeds could not be generated; previous files were kept" >&2
    return "$status"
}

# Find default source file with fallback logic. Tries, in order:
# 1. the data/ directory next to this script (a git checkout or release)
# 2. the Homebrew installation path
# 3. the Docker /app/data/ directory
# 4. ./data/ in the current directory
# 5. the remote GitHub URL
# The scanned project's own ./data must not shadow the built-in feeds, so the
# current directory comes after every installation path.
# Returns path/URL if found, empty string if not found
find_default_source() {
    local source_file="$1"  # e.g., "ghsa.purl" or "osv.purl"

    local script_dir=""
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || script_dir=""
    fi
    if [ -n "$script_dir" ] && [ -f "$script_dir/data/$source_file" ]; then
        echo "$script_dir/data/$source_file"
        return 0
    fi

    # Try Homebrew path
    if command -v brew &> /dev/null; then
        local brew_path
        brew_path="$(brew --prefix)/share/package-checker/data/$source_file"
        if [ -f "$brew_path" ]; then
            echo "$brew_path"
            return 0
        fi
    fi

    # Try Docker /app/data/ directory
    if [ -f "/app/data/$source_file" ]; then
        echo "/app/data/$source_file"
        return 0
    fi

    # Try local ./data/ directory
    if [ -f "./data/$source_file" ]; then
        echo "./data/$source_file"
        return 0
    fi

    # Try remote GitHub URL as last resort
    local github_url="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/$source_file"
    if curl --output /dev/null --silent --head --fail --connect-timeout 10 --max-time 30 "$github_url" 2>/dev/null; then
        echo "$github_url"
        return 0
    fi

    # Nothing found
    echo ""
    return 1
}

# Main execution
# ============================================================================
# Per-ecosystem remediation snippets for GitHub issue bodies.
#
# The GitHub issue builders in src/90-main.sh used to hardcode npm remediation
# (`npm update` / `npm audit`). These helpers make the "how do I fix this"
# guidance ecosystem-aware so a Cargo, Go, PyPI, … finding gets the command a
# developer on THAT stack would actually run. npm keeps its historical
# update/audit guidance so npm-only issues read essentially as before.
# ============================================================================

# Emit the shell/command lines that fix a vulnerable package, for one ecosystem.
# Args:
#   $1 eco     purl type (npm, cargo, golang, pypi, gem, composer, maven,
#              nuget, pub, hex, swift, githubactions, runtime)
#   $2 pkg     package name (or a placeholder like "<package-name>" for the
#              consolidated issue, which is not per-package)
#   $3 indent  optional prefix prepended to every line (e.g. "   " to sit inside
#              a numbered-list code fence). Defaults to no indentation.
# The output is the BODY of a ```bash block; the caller supplies the fence.
fix_commands_for_eco() {
    local eco="$1" pkg="$2" ind="${3:-}"
    case "$eco" in
        npm)
            printf '%snpm update %s\n' "$ind" "$pkg"
            printf '%s# or yarn upgrade %s\n' "$ind" "$pkg"
            printf '%s# or pnpm update %s\n' "$ind" "$pkg"
            printf '%s# auto-fix all advisories: npm audit fix\n' "$ind"
            ;;
        cargo)
            printf '%scargo update -p %s\n' "$ind" "$pkg"
            ;;
        golang)
            printf '%sgo get %s@latest && go mod tidy\n' "$ind" "$pkg"
            ;;
        pypi)
            printf '%spip install --upgrade %s\n' "$ind" "$pkg"
            printf '%s# or with Poetry: poetry update %s\n' "$ind" "$pkg"
            printf '%s# or with uv:     uv lock --upgrade-package %s\n' "$ind" "$pkg"
            ;;
        gem)
            printf '%sbundle update %s\n' "$ind" "$pkg"
            ;;
        composer)
            printf '%scomposer update %s\n' "$ind" "$pkg"
            ;;
        maven)
            printf '%s# Bump %s to the patched version in pom.xml (or build.gradle).\n' "$ind" "$pkg"
            printf '%s# For Gradle lockfiles, refresh them: ./gradlew dependencies --write-locks\n' "$ind"
            ;;
        nuget)
            printf '%sdotnet add package %s\n' "$ind" "$pkg"
            ;;
        pub)
            printf '%sdart pub upgrade %s\n' "$ind" "$pkg"
            ;;
        hex)
            printf '%smix deps.update %s\n' "$ind" "$pkg"
            ;;
        swift)
            printf '%sswift package update %s\n' "$ind" "$pkg"
            ;;
        githubactions)
            printf '%s# Bump the `uses:` ref to the patched tag, e.g. %s@<patched-tag>\n' "$ind" "$pkg"
            ;;
        runtime)
            printf '%s# Upgrade the %s runtime to the fixed version (or later): update\n' "$ind" "$pkg"
            printf '%s# .nvmrc / .node-version / .php-version / .tool-versions, the Docker\n' "$ind"
            printf '%s# base image tag, and composer.json config.platform.php.\n' "$ind"
            ;;
        *)
            printf '%s# Update %s to the latest patched version.\n' "$ind" "$pkg"
            ;;
    esac
}

# Emit the one-line command that re-verifies an ecosystem after updating, used
# as inline code in the issue "Run a security audit" step. Ecosystems without a
# ubiquitous audit tool return a short guidance comment instead.
verify_command_for_eco() {
    case "$1" in
        npm)           echo "npm audit" ;;
        cargo)         echo "cargo audit" ;;
        golang)        echo "govulncheck ./..." ;;
        pypi)          echo "pip-audit" ;;
        gem)           echo "bundle audit check --update  # needs bundler-audit: gem install bundler-audit" ;;
        composer)      echo "composer audit" ;;
        maven)         echo "# re-run your SCA scan (e.g. OWASP dependency-check, Trivy)" ;;
        nuget)         echo "dotnet list package --vulnerable" ;;
        pub)           echo "dart pub outdated" ;;
        hex)           echo "mix deps.audit  # needs mix_audit; mix hex.audit only lists retired packages" ;;
        swift)         echo "# re-resolve and re-scan Package.resolved" ;;
        githubactions) echo "# re-run package-checker (or pin to the patched commit SHA)" ;;
        runtime)       echo "node --version  # or php --version, then re-run package-checker" ;;
        *)             echo "# re-run package-checker after updating" ;;
    esac
}

# Human-readable ecosystem label for issue section headings.
eco_display_name() {
    case "$1" in
        npm)           echo "npm / Node.js" ;;
        pypi)          echo "Python (pip / Poetry / uv)" ;;
        golang)        echo "Go modules" ;;
        maven)         echo "Maven / Gradle (JVM)" ;;
        cargo)         echo "Rust (Cargo)" ;;
        gem)           echo "Ruby (Bundler)" ;;
        composer)      echo "PHP (Composer)" ;;
        nuget)         echo "NuGet (.NET)" ;;
        pub)           echo "Dart / Flutter (pub)" ;;
        hex)           echo "Elixir (Hex)" ;;
        swift)         echo "Swift (SwiftPM)" ;;
        githubactions) echo "GitHub Actions" ;;
        runtime)       echo "Runtime (Node.js / PHP)" ;;
        *)             echo "$1" ;;
    esac
}
# Validate a comma/space-separated ecosystems list (for --ecosystems). Every
# token must be a known lockfile-type alias or a supported purl type.
validate_ecosystems_list() {
    local list="$1"
    list="${list//,/ }"
    local token
    for token in $list; do
        [ -z "$token" ] && continue
        case " $KNOWN_LOCKFILE_ALIASES " in
            *" $token "*) continue ;;
        esac
        case "$token" in
            npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions|runtime) continue ;;
        esac
        echo -e "${RED}❌ Error: Unknown ecosystem '$token' in --ecosystems${NC}"
        echo "Valid values: aliases (${KNOWN_LOCKFILE_ALIASES// /, }) or purl types (npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions, runtime)"
        return 1
    done
    return 0
}

# Emit the space-separated ecosystems (purl types) to load default feeds for.
# Precedence: --ecosystems override > config (CONFIG_ECOSYSTEMS) > auto-detected
# (DETECTED_ECOSYSTEMS). Falls back to npm when nothing was detected so the
# legacy "npm feed always available" behavior is preserved.
resolve_feed_ecosystems() {
    local cli_override="$1"
    local raw=""
    if [ -n "$cli_override" ]; then
        raw="$cli_override"
    elif [ -n "$CONFIG_ECOSYSTEMS" ]; then
        raw="$CONFIG_ECOSYSTEMS"
    fi

    local ecos="" item eco e
    if [ -n "$raw" ]; then
        raw="${raw//,/ }"
        for item in $raw; do
            [ -z "$item" ] && continue
            eco=$(ecosystem_alias_to_purl "$item")
            case " $ecos " in *" $eco "*) ;; *) ecos="${ecos:+$ecos }$eco" ;; esac
        done
    else
        for e in "${!DETECTED_ECOSYSTEMS[@]}"; do
            ecos="${ecos:+$ecos }$e"
        done
    fi

    [ -z "$ecos" ] && ecos="npm"
    printf '%s\n' "$ecos"
}

# Write the name tokens of every discovered project file (plus extra names
# given as arguments) to a temp file and point PREFILTER_TOKENS_FILE at it, so
# parse_purl_to_lookup_eval keeps only the feed entries this project can
# match. A token is a run of [A-Za-z0-9._-] (and each of its dot-separated
# parts), lowercased with runs of - _ . collapsed to "-". One awk pass reads
# every file; split() keeps it linear on minified one-line lockfiles.
# PACKAGE_CHECKER_NO_PREFILTER=1 disables the filter (diagnostics).
build_project_tokens() {
    PREFILTER_TOKENS_FILE=""
    [ "${PACKAGE_CHECKER_NO_PREFILTER:-}" != 1 ] || return 0
    local tokens_file
    tokens_file=$(mktemp) || return 0
    register_temp_file "$tokens_file"
    # awk reads the files itself (no argument list to overflow). A file it
    # cannot read leaves the filter off: a partial token list would silently
    # drop real findings.
    printf '%s\n' "${LOCKFILES}${LOCKFILES:+$'\n'}${PACKAGE_JSON_FILES}" | awk -v names="$*" '
    function scan(line,   cnt, w) {
        cnt = split(line, words, /[^A-Za-z0-9._-]+/)
        for (w = 1; w <= cnt; w++) add(words[w])
        # go.sum escapes capitals ("base64!captcha" is base64Captcha): add
        # the unescaped words too, which lowercase like the feed names.
        if (index(line, "!")) {
            gsub(/!/, "", line)
            cnt = split(line, words, /[^A-Za-z0-9._-]+/)
            for (w = 1; w <= cnt; w++) add(words[w])
        }
    }
    function add(t,   n, parts, cnt, i) {
        if (t == "" || length(t) > 214) return
        n = tolower(t)
        gsub(/[-_.]+/, "-", n)
        seen[n] = 1
        if (index(t, ".")) {
            cnt = split(t, parts, ".")
            for (i = 1; i <= cnt; i++) {
                n = tolower(parts[i])
                gsub(/[-_]+/, "-", n)
                if (n != "") seen[n] = 1
            }
        }
    }
    BEGIN { scan(names) }
    $0 != "" {
        file = $0
        while ((status = (getline line < file)) > 0) scan(line)
        if (status < 0) exit 1
        close(file)
    }
    END { for (t in seen) print t }
    ' > "$tokens_file" || return 0
    PREFILTER_TOKENS_FILE="$tokens_file"
}

# True when DIR declares workspaces (npm/yarn/bun "workspaces", pnpm
# pnpm-workspace.yaml, deno "workspace"): its lockfile then pins the
# dependencies of every member package.json below it.
is_workspace_root() {
    local dir="$1"
    [ -f "$dir/pnpm-workspace.yaml" ] && return 0
    [ -f "$dir/package.json" ] && grep -q '"workspaces"[[:space:]]*:' "$dir/package.json" && return 0
    local deno
    for deno in "$dir/deno.json" "$dir/deno.jsonc"; do
        [ -f "$deno" ] && grep -q '"workspace"[[:space:]]*:' "$deno" && return 0
    done
    return 1
}

# Discover lockfiles and package.json files under the scan directory, populate
# the LOCKFILES / PACKAGE_JSON_FILES globals, and record which ecosystems are
# present in DETECTED_ECOSYSTEMS. Runs BEFORE feed loading so detection can
# drive which default feeds are pulled. Reads main()'s locals (target_path,
# lockfile_types, only_package_json, only_lockfiles, use_github, sbom_files)
# via bash dynamic scope; sets SEARCH_DIR/LOCKFILES/PACKAGE_JSON_FILES/
# SBOM_FILES as globals.
discover_project_files() {
    # Determine the (global) search directory (no trailing slash, so found
    # paths share an exact prefix)
    SEARCH_DIR="${target_path:-.}"
    while [ "${#SEARCH_DIR}" -gt 1 ] && [ "${SEARCH_DIR%/}" != "$SEARCH_DIR" ]; do
        SEARCH_DIR="${SEARCH_DIR%/}"
    done
    if [ "$use_github" = true ] && [ -d "$GITHUB_OUTPUT_DIR" ]; then
        SEARCH_DIR="$GITHUB_OUTPUT_DIR"
    elif [ -n "$target_path" ]; then
        if [ ! -d "$SEARCH_DIR" ]; then
            echo -e "${RED}❌ Error: Target path does not exist: $target_path${NC}"
            exit "$EXIT_ERROR"
        fi
    fi

    # Resolve the lockfile basenames to search for (validates --lockfile-types
    # against the registry-derived alias list). selected_path_entries mirrors
    # selected_basenames for PATH-discovered ecosystems (e.g. GitHub Actions
    # workflows), which are selected by the same --lockfile-types aliases but
    # found via a path predicate instead of a basename (see PATH_ECOSYSTEM_REGISTRY).
    local selected_basenames=()
    local selected_path_entries=()
    local entry bn eco parser alias
    if [ -n "$lockfile_types" ]; then
        local requested=" " t
        local _requested_types
        IFS=',' read -ra _requested_types <<< "$lockfile_types"
        for t in "${_requested_types[@]}"; do
            t="${t//[[:space:]]/}"
            [ -z "$t" ] && continue
            case " $KNOWN_LOCKFILE_ALIASES " in
                *" $t "*) ;;
                *)
                    echo -e "${RED}❌ Unknown lockfile type: $t${NC}"
                    echo "Valid types: ${KNOWN_LOCKFILE_ALIASES// /, }"
                    exit "$EXIT_ERROR" ;;
            esac
            requested="$requested$t "
        done
        for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
            IFS='|' read -r bn eco parser alias <<< "$entry"
            case "$requested" in
                *" $alias "*) selected_basenames+=("$bn") ;;
            esac
        done
        for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
            alias="${entry##*|}"
            case "$requested" in
                *" $alias "*) selected_path_entries+=("$entry") ;;
            esac
        done
    else
        for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
            selected_basenames+=("${entry%%|*}")
        done
        selected_path_entries=("${PATH_ECOSYSTEM_REGISTRY[@]}")
    fi

    # ---- One find for every candidate file ----
    # Ignored directories are pruned (never descended into), and a single
    # traversal collects lockfiles, PATH-discovered files (GitHub Actions
    # workflows, split requirements files) and package.json files.
    local want_locks=false want_pj=false
    [ "$only_package_json" = false ] && want_locks=true
    [ "$only_lockfiles" = false ] && want_pj=true
    local -a match_args=()
    if [ "$want_locks" = true ]; then
        for bn in "${selected_basenames[@]}"; do
            [ ${#match_args[@]} -gt 0 ] && match_args+=( -o )
            match_args+=( -name "$bn" )
        done
        local pentry pglob nglobs palias ng gi
        local -a nglob_arr
        for pentry in "${selected_path_entries[@]}"; do
            # peco/pparser are unused here (dispatch happens later); discard them.
            IFS='|' read -r pglob nglobs _ _ palias <<< "$pentry"
            [ ${#match_args[@]} -gt 0 ] && match_args+=( -o )
            match_args+=( '(' -path "$pglob" '(' )
            IFS=',' read -ra nglob_arr <<< "$nglobs"
            gi=0
            for ng in "${nglob_arr[@]}"; do
                [ "$gi" -gt 0 ] && match_args+=( -o )
                match_args+=( -name "$ng" )
                gi=$((gi + 1))
            done
            match_args+=( ')' ')' )
        done
    fi
    # Runtime version files (src/50-ecosystems/65-runtimes.sh) ride on the same
    # traversal, whatever --only-lockfiles / --lockfile-types select.
    local want_runtime=true
    [ "$runtime_check" != false ] || want_runtime=false
    if [ "$want_pj" = true ] || [ "$want_runtime" = true ]; then
        [ ${#match_args[@]} -gt 0 ] && match_args+=( -o )
        match_args+=( -name "package.json" )
    fi
    if [ "$want_runtime" = true ]; then
        local rname
        for rname in "${RUNTIME_FILE_NAMES[@]}"; do
            match_args+=( -o -name "$rname" )
        done
        match_args+=( -o '(' -path '*/.github/workflows/*' '(' -name '*.yml' -o -name '*.yaml' ')' ')' )
    fi

    local found=""
    if [ ${#match_args[@]} -gt 0 ]; then
        local -a find_args=( "$SEARCH_DIR" )
        local ignore_path
        if [ ${#CONFIG_IGNORE_PATHS[@]} -gt 0 ]; then
            find_args+=( '(' )
            local first_ignore=true
            for ignore_path in "${CONFIG_IGNORE_PATHS[@]}"; do
                [ -n "$ignore_path" ] || continue
                [ "$first_ignore" = true ] || find_args+=( -o )
                first_ignore=false
                find_args+=( -path "*/${ignore_path%/}" )
            done
            find_args+=( ')' -prune -o )
        fi
        find_args+=( '(' "${match_args[@]}" ')' -type f -print )
        # An unreadable directory must not abort the scan (set -e): report it
        # and keep whatever was found.
        if ! found=$(find "${find_args[@]}" 2>/dev/null); then
            echo -e "${YELLOW}⚠️  Warning: some directories under $SEARCH_DIR could not be read; results may be incomplete${NC}" >&2
        fi
    fi

    # ---- Drop git-ignored files ----
    # The repository is the one containing the scanned directory (not the
    # current one), checked once for all files. Files fetched from GitHub are
    # never filtered: the output directory itself is often git-ignored.
    # Skipped files are listed; --include-gitignored scans them.
    if [ -n "$found" ] && [ "$include_gitignored" = false ] && [ "$SEARCH_DIR" != "$GITHUB_OUTPUT_DIR" ] &&
        git -C "$SEARCH_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        local prefix="${SEARCH_DIR%/}/" ignored
        ignored=$(printf '%s\n' "$found" | while IFS= read -r f; do printf '%s\n' "${f#"$prefix"}"; done |
            git -C "$SEARCH_DIR" check-ignore --stdin 2>/dev/null) || true
        if [ -n "$ignored" ]; then
            found=$(printf '%s\n' "$found" | awk -v prefix="$prefix" '
                NR == FNR { ignored[$0] = 1; next }
                { rel = $0; if (index(rel, prefix) == 1) rel = substr(rel, length(prefix) + 1) }
                !(rel in ignored)' <(printf '%s\n' "$ignored") -)
            local ignored_count
            ignored_count=$(printf '%s\n' "$ignored" | wc -l | tr -d ' ')
            echo -e "${YELLOW}⚠️  Skipping $ignored_count git-ignored file(s) (use --include-gitignored to scan them):${NC}"
            printf '%s\n' "$ignored" | head -n 10 | sed 's/^/      /'
            [ "$ignored_count" -le 10 ] || echo "      ... and $((ignored_count - 10)) more"
            echo ""
        fi
    fi

    # ---- Split lockfiles, package.json files and runtime version files ----
    # A runtime pattern may also find a file no lockfile selection asked for
    # (composer.lock under --lockfile-types npm): only selected names and
    # paths become lockfiles.
    LOCKFILES=""
    PACKAGE_JSON_FILES=""
    RUNTIME_FILES=""
    local -A lock_basenames=()
    for bn in "${selected_basenames[@]}"; do lock_basenames["$bn"]=1; done
    local file base is_runtime is_lock pentry pglob nglobs ng
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        base="${file##*/}"
        is_runtime=false
        if [ "$want_runtime" = true ] && runtime_file_kind "$file"; then
            RUNTIME_FILES+="${RUNTIME_FILES:+$'\n'}$file"
            is_runtime=true
        fi
        if [ "$base" = "package.json" ]; then
            [ "$want_pj" = false ] || PACKAGE_JSON_FILES+="${PACKAGE_JSON_FILES:+$'\n'}$file"
            continue
        fi
        [ "$want_locks" = true ] || continue
        is_lock=true
        if [ "$is_runtime" = true ] && [ -z "${lock_basenames[$base]+x}" ]; then
            is_lock=false
            for pentry in "${selected_path_entries[@]}"; do
                IFS='|' read -r pglob nglobs _ _ _ <<< "$pentry"
                # shellcheck disable=SC2053 # glob patterns from the registry
                [[ "$file" == $pglob ]] || continue
                IFS=',' read -ra nglob_arr <<< "$nglobs"
                for ng in "${nglob_arr[@]}"; do
                    # shellcheck disable=SC2053
                    if [[ "$base" == $ng ]]; then is_lock=true; break 2; fi
                done
            done
        fi
        [ "$is_lock" = false ] || LOCKFILES+="${LOCKFILES:+$'\n'}$file"
    done <<< "$found"
    RUNTIME_FILES=$(runtime_files_with_versions "$RUNTIME_FILES")

    # ---- CycloneDX SBOMs given with --sbom ----
    # Scanned like lockfiles, whatever their name or location (often a
    # git-ignored build output such as target/bom.json).
    local sbom
    for sbom in "${sbom_files[@]}"; do
        [ -n "${SBOM_FILES[$sbom]+x}" ] && continue
        SBOM_FILES["$sbom"]=1
        LOCKFILES+="${LOCKFILES:+$'\n'}$sbom"
    done

    # ---- package.json files already covered by a lockfile ----
    # A lockfile pins what is installed; the manifest only declares ranges
    # (lodash ^4.17.0 would be checked as 4.17.0 while the lock has 4.18.1).
    # Skip a package.json whose directory holds an npm-family lockfile, or
    # whose ancestor (up to the scan root) is a workspace root with one.
    SKIPPED_PACKAGE_JSON_COUNT=0
    if [ -n "$PACKAGE_JSON_FILES" ] && [ -n "$LOCKFILES" ]; then
        local -A npm_lock_dirs=()
        local lf
        while IFS= read -r lf; do
            case "${lf##*/}" in
                package-lock.json|npm-shrinkwrap.json|yarn.lock|pnpm-lock.yaml|bun.lock|deno.lock)
                    npm_lock_dirs["${lf%/*}"]=1 ;;
            esac
        done <<< "$LOCKFILES"
        if [ ${#npm_lock_dirs[@]} -gt 0 ]; then
            local kept="" pj dir covered
            while IFS= read -r pj; do
                [ -n "$pj" ] || continue
                dir="${pj%/*}"
                covered=false
                if [ -n "${npm_lock_dirs[$dir]+x}" ]; then
                    covered=true
                else
                    while [ "$dir" != "$SEARCH_DIR" ] && [[ "$dir" == */* ]]; do
                        dir="${dir%/*}"
                        if [ -n "${npm_lock_dirs[$dir]+x}" ] && is_workspace_root "$dir"; then
                            covered=true
                            break
                        fi
                    done
                fi
                if [ "$covered" = true ]; then
                    SKIPPED_PACKAGE_JSON_COUNT=$((SKIPPED_PACKAGE_JSON_COUNT + 1))
                else
                    kept+="${kept:+$'\n'}$pj"
                fi
            done <<< "$PACKAGE_JSON_FILES"
            PACKAGE_JSON_FILES="$kept"
        fi
    fi

    # ---- Record detected ecosystems ----
    if [ -n "$LOCKFILES" ]; then
        local lfile b e _pe
        while IFS= read -r lfile; do
            [ -z "$lfile" ] && continue
            if [ -n "${SBOM_FILES[$lfile]+x}" ]; then
                for e in $(cyclonedx_components "$lfile" | cut -d'|' -f1 | sort -u); do
                    case "$e" in
                        npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions)
                            DETECTED_ECOSYSTEMS["$e"]=1 ;;
                    esac
                done
                continue
            fi
            b="${lfile##*/}"
            e="${LOCKFILE_ECO[$b]:-}"
            # Path-discovered files (workflows) have no basename row; resolve
            # their ecosystem by path so detection pulls the right default feed.
            if [ -z "$e" ] && _pe=$(path_ecosystem_match "$lfile"); then
                e="${_pe#*|}"; e="${e%%|*}"
            fi
            [ -n "$e" ] && DETECTED_ECOSYSTEMS["$e"]=1
        done <<< "$LOCKFILES"
    fi
    if [ -n "$PACKAGE_JSON_FILES" ]; then
        DETECTED_ECOSYSTEMS["npm"]=1
    fi
}

# Report a project file that cannot be read: it was not scanned, so the run
# cannot end with a clean result (see the end of main).
report_unreadable_file() {
    echo -e "${RED}❌ [$1] Cannot read this file: it was not scanned${NC}"
    UNREADABLE_FILE_COUNT=$((UNREADABLE_FILE_COUNT + 1))
}

# Print the merged advisories of one finding ("rec||rec", each record
# "severity;ghsa;cve;source;fix;id"). Returns non-zero when nothing was printed.
print_advisories() {
    local advisories="$1" advisory severity ghsa cve source fix id color printed=1
    while [ -n "$advisories" ]; do
        advisory="${advisories%%||*}"
        if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
        IFS=';' read -r severity ghsa cve source fix id <<< "$advisory"
        if [ -n "$severity" ]; then
            severity_rank "$severity"
            case "$SEV_RANK" in
                4) color="$RED" ;;
                3) color="$YELLOW" ;;
                2) color="$BLUE" ;;
                *) color="$NC" ;;
            esac
            echo -e "      ${color}Severity: $severity${NC}"
            printed=0
        fi
        if [ -n "$ghsa" ]; then
            case ", $source, " in
                *", ghsa, "*) echo -e "      ${BLUE}GHSA: $ghsa (https://github.com/advisories/$ghsa)${NC}" ;;
                *", osv, "*) echo -e "      ${BLUE}GHSA: $ghsa (https://osv.dev/vulnerability/$ghsa)${NC}" ;;
                *) echo -e "      ${BLUE}GHSA: $ghsa${NC}" ;;
            esac
            printed=0
        fi
        if [ -n "$cve" ]; then
            echo -e "      ${BLUE}CVE: $cve (https://nvd.nist.gov/vuln/detail/$cve)${NC}"
            printed=0
        fi
        if [ -n "$id" ]; then
            echo -e "      ${BLUE}ID: $id (https://osv.dev/vulnerability/$id)${NC}"
            printed=0
        fi
        if [ -n "$source" ]; then
            echo -e "      ${BLUE}Source: $source${NC}"
            printed=0
        fi
        if [ -n "$fix" ]; then
            echo -e "      ${GREEN}Fix: upgrade to >= $fix${NC}"
            printed=0
        fi
    done
    return "$printed"
}

main() {
    local use_config=true
    local cli_sources=false
    local use_default_ghsa=false
    local custom_config=""
    local custom_sources=()
    local use_github=false
    local name=""
    local package_version=""
    local ecosystem="npm"
    local export_json_file=""
    local export_csv_file=""
    local only_package_json=false
    local only_lockfiles=false
    local lockfile_types=""
    local target_path=""
    local default_feeds=""
    local cli_ecosystems=""
    local sbom_files=()
    local go_reachability=false
    local runtime_check=""   # "" = not set on the command line (config decides)
    local include_gitignored=false

    # Any unexpected failure that aborts the run (set -e) exits with
    # EXIT_ERROR, never with 1, which means "vulnerable packages found".
    # Command substitutions keep their usual non-fatal behavior.
    set -E
    trap '[ "$BASH_SUBSHELL" -ne 0 ] || exit "$EXIT_ERROR"' ERR

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--source|-f|--format|--csv-columns|-c|--config|--github-org|--github-repo|--github-token|--github-output|--package-name|--package-version|--ecosystem|--ecosystems|--lockfile-types|--sbom)
                if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
                    echo "Error: $1 requires a value"
                    exit "$EXIT_ERROR"
                fi
                ;;
        esac
        case $1 in
            -h|--help)
                if [[ "$2" == "format" ]]; then
                    show_format_help
                else
                    show_help
                fi
                ;;
            --help-ai)
                show_ai_help "$2"
                ;;
            -v|--version)
                show_version
                ;;
            -s|--source)
                custom_sources+=("$2|")
                cli_sources=true
                shift 2
                ;;
            --default-source-ghsa)
                # Record intent; the feed is resolved per detected ecosystem
                # after project discovery (see the source-loading section).
                default_feeds="ghsa"
                cli_sources=true
                use_default_ghsa=true
                shift
                ;;
            --default-source-osv)
                default_feeds="osv"
                cli_sources=true
                shift
                ;;
            --default-source-ghsa-osv)
                default_feeds="ghsa osv"
                cli_sources=true
                shift
                ;;
            -f|--format|--csv-columns)
                # Both qualify the preceding -s/--source, in either order:
                # rebuild its "url|format|columns" entry from its parts.
                if [ ${#custom_sources[@]} -eq 0 ]; then
                    echo -e "${RED}❌ Error: $1 must follow the -s/--source it applies to${NC}"
                    exit "$EXIT_ERROR"
                fi
                local last_idx=$((${#custom_sources[@]} - 1))
                local src_url src_format src_columns
                IFS='|' read -r src_url src_format src_columns <<< "${custom_sources[$last_idx]}"
                if [ "$1" = "--csv-columns" ]; then
                    src_columns="$2"
                else
                    src_format="$2"
                fi
                custom_sources[$last_idx]="$src_url|$src_format|$src_columns"
                shift 2
                ;;
            -c|--config)
                custom_config="$2"
                shift 2
                ;;
            --no-config)
                use_config=false
                shift
                ;;
            --github-org)
                GITHUB_ORG="$2"
                use_github=true
                shift 2
                ;;
            --github-repo)
                GITHUB_REPO="$2"
                use_github=true
                shift 2
                ;;
            --github-token)
                GITHUB_TOKEN="$2"
                shift 2
                ;;
            --github-output)
                GITHUB_OUTPUT_DIR="$2"
                shift 2
                ;;
            --github-only)
                GITHUB_ONLY=true
                use_github=true
                shift
                ;;
            --create-multiple-issues)
                CREATE_GITHUB_ISSUE=true
                shift
                ;;
            --create-single-issue)
                CREATE_SINGLE_ISSUE=true
                shift
                ;;
            --package-name)
                name="$2"
                shift 2
                ;;
            --package-version)
                package_version="$2"
                shift 2
                ;;
            --ecosystem)
                ecosystem="$2"
                shift 2
                ;;
            --export-json|--export-csv)
                # The file name is optional: a following option or an existing
                # directory (the scan PATH) is not taken as the file name.
                local export_option="$1" export_file="vulnerabilities.${1#--export-}"
                if [ -n "${2:-}" ] && [[ "$2" != -* ]] && [ ! -d "$2" ]; then
                    export_file="$2"
                    shift
                fi
                if [ "$export_option" = "--export-json" ]; then
                    export_json_file="$export_file"
                else
                    export_csv_file="$export_file"
                fi
                shift
                ;;
            --fetch-all)
                # Optional DIR argument (default: data). Generates GHSA + OSV
                # feeds for ALL supported ecosystems.
                check_dependencies curl jq git unzip
                local fetch_dir="data"
                [ -z "${2:-}" ] || [[ "$2" == -* ]] || fetch_dir="$2"
                fetch_all "$fetch_dir" || exit "$EXIT_ERROR"
                exit 0
                ;;
            --fetch-osv)
                # Optional argument:
                #   (none)            -> all ecosystems into data/
                #   comma/space list  -> those ecosystems into data/ (e.g. pypi,go)
                #   legacy file path  -> npm feed into that file's directory
                check_dependencies curl jq unzip
                case "${2:-}" in
                    ""|-*) fetch_osv ;;
                    */) FEED_OUTPUT_DIR="${2%/}" fetch_osv ;;
                    */*|*.purl)
                        if [ -d "$2" ]; then FEED_OUTPUT_DIR="$2" fetch_osv
                        else FEED_OUTPUT_DIR="$(dirname "$2")" fetch_osv npm; fi ;;
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"; fetch_osv "${_fetch_ecos[@]}" ;;
                esac || exit "$EXIT_ERROR"
                exit 0
                ;;
            --fetch-ghsa)
                # Same argument semantics as --fetch-osv (single clone, all ecos).
                check_dependencies jq git
                case "${2:-}" in
                    ""|-*) fetch_ghsa ;;
                    */) FEED_OUTPUT_DIR="${2%/}" fetch_ghsa ;;
                    */*|*.purl)
                        if [ -d "$2" ]; then FEED_OUTPUT_DIR="$2" fetch_ghsa
                        else FEED_OUTPUT_DIR="$(dirname "$2")" fetch_ghsa npm; fi ;;
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"; fetch_ghsa "${_fetch_ecos[@]}" ;;
                esac || exit "$EXIT_ERROR"
                exit 0
                ;;
            --fetch-runtime)
                # Optional DIR argument (default: data): writes osv-runtime.purl.
                check_dependencies curl jq unzip
                local runtime_dir="data"
                [ -z "${2:-}" ] || [[ "$2" == -* ]] || runtime_dir="$2"
                FEED_OUTPUT_DIR="$runtime_dir" fetch_runtime || exit "$EXIT_ERROR"
                exit 0
                ;;
            --no-runtime-check)
                runtime_check=false
                shift
                ;;
            --include-gitignored)
                include_gitignored=true
                shift
                ;;
            --only-package-json)
                only_package_json=true
                shift
                ;;
            --only-lockfiles)
                only_lockfiles=true
                shift
                ;;
            --lockfile-types)
                lockfile_types="$2"
                shift 2
                ;;
            --ecosystems)
                cli_ecosystems="$2"
                shift 2
                ;;
            --go-reachability)
                go_reachability=true
                shift
                ;;
            --sbom)
                if [ ! -f "$2" ]; then
                    echo -e "${RED}❌ Error: SBOM file not found: $2${NC}"
                    exit "$EXIT_ERROR"
                fi
                sbom_files+=("$2")
                shift 2
                ;;
            -*)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit "$EXIT_ERROR"
                ;;
            *)
                # Positional argument - treat as target path
                if [ -z "$target_path" ]; then
                    target_path="$1"
                    shift
                else
                    echo -e "${RED}❌ Error: Multiple target paths specified${NC}"
                    echo "Use --help for usage information"
                    exit "$EXIT_ERROR"
                fi
                ;;
        esac
    done

    # Validate mutually exclusive options
    if [ "$only_package_json" = true ] && [ "$only_lockfiles" = true ]; then
        echo -e "${RED}❌ Error: --only-package-json and --only-lockfiles are mutually exclusive${NC}"
        echo "Use --help for usage information"
        exit "$EXIT_ERROR"
    fi

    # Validate lockfile-types only makes sense with lockfiles
    if [ -n "$lockfile_types" ] && [ "$only_package_json" = true ]; then
        echo -e "${RED}❌ Error: --lockfile-types cannot be used with --only-package-json${NC}"
        echo "Use --help for usage information"
        exit "$EXIT_ERROR"
    fi

    # Validate --ecosystem against the supported purl types
    case "$ecosystem" in
        npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions|runtime)
            ;;
        *)
            echo -e "${RED}❌ Error: Unsupported ecosystem '$ecosystem'${NC}"
            echo "Valid ecosystems: npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions, runtime"
            exit "$EXIT_ERROR"
            ;;
    esac

    # Build the ecosystem lookup tables from the registry (single source of
    # truth for discovery, dispatch and default-feed resolution).
    build_ecosystem_tables

    # Validate the --ecosystems feed-loading override (aliases or purl types).
    if [ -n "$cli_ecosystems" ]; then
        validate_ecosystems_list "$cli_ecosystems" || exit "$EXIT_ERROR"
    fi

    check_dependencies

    # --package-name: look the package up in the project through a virtual
    # purl entry (NAME@VERSION, or every version when none is given) and, for
    # an exact --package-version, check that version against the feeds. Only
    # this package is reported; without another source, the default feed of
    # --ecosystem is loaded.
    local package_lookup_file=""
    if [ -n "$name" ]; then
        if ! package_lookup_file=$(mktemp); then
            echo -e "${RED}❌ Error: Unable to create a temporary file${NC}"
            exit "$EXIT_ERROR"
        fi
        register_temp_file "$package_lookup_file"
        printf 'pkg:%s/%s@%s\n' "$ecosystem" "$name" "${package_version:-*}" > "$package_lookup_file"
        canonical_package_name "$ecosystem" "$name"
        PACKAGE_FILTER="$ecosystem:$CANON_NAME"
        cli_sources=true
    fi

    echo "╔════════════════════════════════════════════════════╗"
    echo "║       Package Vulnerability Checker                ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""

    # Configuration must precede fetching and discovery: it supplies GitHub
    # settings, exclusions and the default-feed ecosystem override.
    # Options and GitHub settings always apply; the configured sources only
    # when no source was given on the command line. --no-config skips the
    # default file, but an explicit -c/--config is always read.
    local sources_loaded=false config_to_use=""
    if [ -n "$custom_config" ]; then
        config_to_use="$custom_config"
    elif [ "$use_config" = true ] && [ -f "$CONFIG_FILE" ]; then
        config_to_use="$CONFIG_FILE"
    fi
    if [ -n "$config_to_use" ]; then
        if [ ! -f "$config_to_use" ]; then
            echo "Error: Configuration file not found: $config_to_use"
            exit "$EXIT_ERROR"
        fi
        local config_sources=true
        [ "$cli_sources" = false ] || config_sources=false
        load_config_file "$config_to_use" "$config_sources" || exit "$EXIT_ERROR"
        validate_ecosystems_list "$CONFIG_ECOSYSTEMS" || exit "$EXIT_ERROR"
        [ "$LOADED_SOURCE_COUNT" -eq 0 ] || sources_loaded=true
        if [ -n "$GITHUB_REPO" ] || [ -n "$GITHUB_ORG" ]; then
            use_github=true
        fi
    fi

    if { [ "$CREATE_GITHUB_ISSUE" = true ] || [ "$CREATE_SINGLE_ISSUE" = true ]; } && [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${RED}❌ Error: --create-multiple-issues and --create-single-issue require a GitHub token${NC}"
        echo "   Use --github-token or set the GITHUB_TOKEN environment variable"
        exit "$EXIT_ERROR"
    fi

    # Fetch packages from GitHub if requested
    if [ "$use_github" = true ]; then
        fetch_github_packages || exit "$EXIT_ERROR"
        
        # If --github-only, exit after fetching
        if [ "$GITHUB_ONLY" = true ]; then
            echo -e "${GREEN}✅ GitHub packages fetched successfully. Use without --github-only to analyze.${NC}"
            exit 0
        fi
    fi

    # Runtime versions are checked unless --no-runtime-check or
    # options.runtime_check=false; a --package-name lookup only checks a
    # runtime when it names one (--ecosystem runtime).
    [ -n "$runtime_check" ] || runtime_check="$CONFIG_RUNTIME_CHECK"
    if [ -n "$name" ] && [ "$ecosystem" != runtime ]; then
        runtime_check=false
    fi

    # Discover project files and detect ecosystems BEFORE loading feeds, so we
    # only pull the default feeds the detected ecosystems actually need. Only
    # skipped git-ignored files are reported here; the results are
    # printed/analyzed after the lookup build.
    discover_project_files

    # A truncated project file is an incomplete scan, never a clean result.
    # Validate strict JSON only: bun.lock is JSONC and has a separate grammar.
    local project_input
    while IFS= read -r project_input; do
        [ -z "$project_input" ] && continue
        # Unreadable files are reported when they are analyzed.
        [ -r "$project_input" ] || continue
        case "${project_input##*/}" in
            package.json|package-lock.json|npm-shrinkwrap.json|Pipfile.lock|composer.lock|packages.lock.json|Package.resolved|deno.lock) ;;
            *) [ -n "${SBOM_FILES[$project_input]+x}" ] || continue ;;
        esac
        if ! json_is_valid_file "$project_input"; then
            echo -e "${RED}❌ Invalid JSON in project file: $project_input${NC}"
            exit "$EXIT_ERROR"
        fi
    done <<< "${LOCKFILES}${LOCKFILES:+$'\n'}${PACKAGE_JSON_FILES}"

    # Feed entries are pre-filtered on the names this project can contain
    # (plus the runtime names when a runtime version file was found).
    local -a token_names=()
    [ -z "$name" ] || token_names+=("$name")
    # shellcheck disable=SC2206 # space-separated list of plain names
    [ -z "$RUNTIME_FILES" ] || token_names+=($RUNTIME_FEED_PACKAGES)
    build_project_tokens "${token_names[@]}"

    # 2. Explicit --source entries load unconditionally (no ecosystem filtering)
    if [ ${#custom_sources[@]} -gt 0 ]; then
        local source url format columns
        for source in "${custom_sources[@]}"; do
            IFS='|' read -r url format columns <<< "$source"
            load_data_source "$url" "$format" "Custom Source" "$columns" || exit "$EXIT_ERROR"
        done
        sources_loaded=true
    fi

    # 3. Default feeds (GHSA/OSV), resolved per detected ecosystem. Explicit
    #    --default-source-* flags set $default_feeds; otherwise, when nothing has
    #    loaded yet, fall back to the implicit default (GHSA).
    local feeds_to_load="$default_feeds"
    local implicit_default=false
    if [ -z "$feeds_to_load" ] && [ "$sources_loaded" = false ]; then
        feeds_to_load="ghsa"
        implicit_default=true
    fi

    if [ -n "$feeds_to_load" ]; then
        if [ "$implicit_default" = true ]; then
            echo -e "${BLUE}ℹ️  No data source specified, using default GHSA source${NC}"
            echo ""
        fi

        # Ecosystems to load feeds for: --ecosystems > config > auto-detected;
        # a --package-name lookup only needs its own ecosystem.
        local feed_ecos
        if [ -n "$name" ] && [ -z "$cli_ecosystems" ]; then
            feed_ecos="$ecosystem"
        else
            feed_ecos=$(resolve_feed_ecosystems "$cli_ecosystems")
        fi

        local eco feed feed_file feed_path feed_label feeds_loaded=0 feed_entries=0
        for eco in $feed_ecos; do
            # Runtime advisories have a single feed of their own (step 3b).
            [ "$eco" != runtime ] || continue
            for feed in $feeds_to_load; do
                feed_file=$(default_feed_filename "$feed" "$eco")
                # NB: find_default_source returns non-zero when a feed is
                # missing; `|| true` keeps `set -e` from aborting so we can warn
                # and continue (a plain assignment would exit the script).
                feed_path=$(find_default_source "$feed_file") || true
                if [ -n "$feed_path" ]; then
                    feed_label=$(printf '%s' "$feed" | tr '[:lower:]' '[:upper:]')
                    echo -e "${GREEN}✓ Using ${feed_label} source: $feed_path${NC}"
                    echo ""
                    load_data_source "$feed_path" "purl" "Default ${feed_label} Source" "" || exit "$EXIT_ERROR"
                    sources_loaded=true
                    feeds_loaded=$((feeds_loaded + 1))
                    feed_entries=$((feed_entries + LAST_SOURCE_ENTRY_COUNT))
                else
                    echo -e "${YELLOW}⚠️  Warning: Unable to find ${feed} feed for ${eco} (${feed_file})${NC}"
                fi
            done
        done

        # A default feed always lists advisories: none at all means the feed
        # files are empty or unreadable, and a clean result would be a lie.
        if [ "$feeds_loaded" -gt 0 ] && [ "$feed_entries" -eq 0 ]; then
            echo -e "${RED}❌ Error: the default vulnerability feeds are empty or unreadable${NC}"
            exit "$EXIT_ERROR"
        fi
    fi

    # 3b. Runtime advisories (Node.js, PHP): one feed, loaded whenever the
    #     project pins a runtime version, whatever the GHSA/OSV choice.
    local runtime_feed_loaded=false
    if { [ "$runtime_check" != false ] && [ -n "$RUNTIME_FILES" ]; } ||
        { [ -n "$name" ] && [ "$ecosystem" = runtime ]; }; then
        local runtime_feed
        runtime_feed=$(find_default_source "osv-runtime.purl") || true
        if [ -n "$runtime_feed" ]; then
            echo -e "${GREEN}✓ Using runtime source: $runtime_feed${NC}"
            echo ""
            load_data_source "$runtime_feed" "purl" "Runtime advisories (Node.js, PHP)" "" || exit "$EXIT_ERROR"
            sources_loaded=true
            runtime_feed_loaded=true
        else
            echo -e "${YELLOW}⚠️  Warning: Unable to find the runtime feed (osv-runtime.purl); runtime versions are not checked${NC}"
        fi
    fi

    # 4. --package-name: check the exact version itself, then add the lookup
    #    entry (loaded last so the version check cannot match it).
    if [ -n "$name" ]; then
        if [ -n "$package_version" ] && [[ "$package_version" != *[\ \<\>=\^~*,\|]* ]]; then
            check_vulnerability "$ecosystem" "$CANON_NAME" "$package_version" "--package-name" || true
        fi
        load_data_source "$package_lookup_file" "purl" "Package lookup: $name" "" || exit "$EXIT_ERROR"
        sources_loaded=true
    fi

    if [ "$sources_loaded" = false ]; then
        echo -e "${RED}❌ Error: Unable to find any vulnerability data source${NC}"
        echo ""
        echo "By default, package-checker uses the built-in GHSA feed."
        echo "If you see this message, no source could be found or loaded."
        echo ""
        echo "Tried the following locations for each detected ecosystem:"
        echo "  - Next to the script: <script dir>/data/"
        echo "  - Homebrew: \$(brew --prefix)/share/package-checker/data/"
        echo "  - Docker: /app/data/"
        echo "  - Local: ./data/"
        echo "  - Remote: https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/"
        echo ""
        echo "You can explicitly specify a data source using:"
        echo "  --default-source-ghsa    Use default GHSA source"
        echo "  --default-source-osv     Use default OSV source"
        echo "  --default-source-ghsa-osv         Use both GHSA and OSV sources"
        echo "  --source <URL>           Use custom vulnerability database"
        echo "  A .package-checker.config.json file"
        echo ""
        echo "Use --help for more information"
        exit "$EXIT_ERROR"
    fi

    # Count unique vulnerable packages across every loaded source.
    local total_packages=0 pkg
    local -A unique_pkgs_temp=()
    for pkg in "${!VULN_EXACT_LOOKUP[@]}" "${!VULN_RANGE_LOOKUP[@]}"; do
        unique_pkgs_temp["$pkg"]=1
    done
    total_packages=${#unique_pkgs_temp[@]}
    unset unique_pkgs_temp

    if [ -n "${PREFILTER_TOKENS_FILE:-}" ]; then
        echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages relevant to this project (of ${TOTAL_SOURCE_ENTRIES:-0} entries loaded)${NC}"
    else
        echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages${NC}"
    fi
    if [ "${TOTAL_SOURCE_ENTRIES:-0}" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  The data sources contain no vulnerability entry${NC}"
    fi

    echo -e "${GREEN}✅ Lookup tables ready (${#VULN_EXACT_LOOKUP[@]} packages with exact versions, ${#VULN_RANGE_LOOKUP[@]} with ranges)${NC}"
    echo ""

    # Report the directory being scanned (files were discovered before feed
    # loading; see discover_project_files).
    if [ "$use_github" = true ] && [ -d "$GITHUB_OUTPUT_DIR" ]; then
        echo -e "${BLUE}📂 Analyzing packages from GitHub: $SEARCH_DIR${NC}"
        echo ""
    elif [ -n "$target_path" ]; then
        echo -e "${BLUE}📂 Scanning directory: $SEARCH_DIR${NC}"
        echo ""
    fi

    # Search for lockfiles
    echo "🔍 Searching for lockfiles and package.json files..."
    echo ""

    if [ -z "$LOCKFILES" ]; then
        if [ "$only_package_json" = true ]; then
            echo "   ⏩ Skipping lockfiles (--only-package-json specified)"
        else
            echo "   ℹ️  No lockfiles found"
        fi
    else
        LOCKFILE_COUNT=$(echo "$LOCKFILES" | wc -l | tr -d ' ')
        if [ -n "$lockfile_types" ]; then
            echo "📦 Analyzing $LOCKFILE_COUNT lockfile(s) [types: $lockfile_types]..."
        else
            echo "📦 Analyzing $LOCKFILE_COUNT lockfile(s)..."
        fi

        while IFS= read -r lockfile; do
            [ -z "$lockfile" ] && continue
            if [ ! -r "$lockfile" ]; then
                report_unreadable_file "$lockfile"
                continue
            fi
            lockname="${lockfile##*/}"
            local lock_parser="${LOCKFILE_PARSER[$lockname]:-}"
            if [ -n "${SBOM_FILES[$lockfile]+x}" ]; then
                analyze_cyclonedx_inventory "$lockfile"
            elif [ -n "$lock_parser" ]; then
                "$lock_parser" "$lockfile" "${LOCKFILE_ECO[$lockname]}"
            else
                # Path-discovered ecosystem (e.g. GitHub Actions workflows):
                # no basename key — resolve the parser by path pattern.
                local _pe _pe_parser _pe_eco _pe_alias
                if _pe=$(path_ecosystem_match "$lockfile"); then
                    IFS='|' read -r _pe_parser _pe_eco _pe_alias <<< "$_pe"
                    "$_pe_parser" "$lockfile" "$_pe_eco"
                fi
            fi
        done <<< "$LOCKFILES"
    fi

    # Analyze package.json files (discovered before feed loading)
    if [ "${SKIPPED_PACKAGE_JSON_COUNT:-0}" -gt 0 ]; then
        echo "   ⏩ Skipping $SKIPPED_PACKAGE_JSON_COUNT package.json file(s) covered by a lockfile"
    fi
    if [ -z "$PACKAGE_JSON_FILES" ]; then
        if [ "$only_lockfiles" = true ]; then
            echo "   ⏩ Skipping package.json files (--only-lockfiles specified)"
        elif [ "${SKIPPED_PACKAGE_JSON_COUNT:-0}" -eq 0 ]; then
            echo "   ℹ️  No package.json files found"
        fi
    else
        PACKAGE_COUNT=$(echo "$PACKAGE_JSON_FILES" | wc -l | tr -d ' ')
        echo "📦 Analyzing $PACKAGE_COUNT package.json file(s) (declared versions: no lockfile covers them)..."
        
        # Build regex pattern of dependency types to match
        local dep_types_pattern=$(printf '%s|' "${CONFIG_DEPENDENCY_TYPES[@]}")
        dep_types_pattern="${dep_types_pattern%|}"  # Remove trailing |
        
        while IFS= read -r package_file; do
            if [ ! -r "$package_file" ]; then
                report_unreadable_file "$package_file"
                continue
            fi
            # Track vulnerabilities found in this file
            local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

            # Use awk to extract all dependencies efficiently
            local deps
            deps=$(awk -v dep_pattern="$dep_types_pattern" '
            BEGIN { depth=0; active=0; pending=0 }
            {
                line = $0
                for (i = 1; i <= length(line); i++) {
                    c = substr(line, i, 1)
                    if (c == "\"") {
                        token = ""
                        for (i++; i <= length(line); i++) {
                            c = substr(line, i, 1)
                            if (c == "\\") {
                                token = token c substr(line, ++i, 1)
                            } else if (c == "\"") {
                                break
                            } else token = token c
                        }
                        rest = substr(line, i + 1)
                        if (rest ~ /^[[:space:]]*:/) {
                            if (depth == 1) pending = (token ~ ("^(" dep_pattern ")$"))
                            else if (active && depth == 2) pkg = token
                        } else if (active && depth == 2 && pkg != "") {
                            # Only semver specs name a version: git+, github:,
                            # catalog:, patch:, file:, workspace:, npm: aliases,
                            # URLs and dist-tags (latest, next) do not.
                            ver = token
                            gsub(/^[\\^~>=<v[:space:]]+/, "", ver)
                            gsub(/[[:space:]].*/, "", ver)
                            if (ver ~ /^[0-9]/ && ver !~ /:/) print pkg "|" ver
                            pkg = ""
                        } else if (depth == 1) {
                            pending = 0
                        }
                    } else if (depth == 1 && c ~ /[^[:space:],:{}]/) {
                        # A non-object value ("dependencies": null) closes the
                        # pending dependency section without opening it.
                        pending = 0
                    } else if (c == "{") {
                        if (depth == 1) { active = pending; pending = 0; pkg = "" }
                        depth++
                    } else if (c == "}") {
                        if (depth == 2) { active = 0; pkg = "" }
                        depth--
                    }
                }
            }
            ' "$package_file" 2>/dev/null | sort -u)

            # Check each dependency against vulnerability database
            while IFS='|' read -r pkg_name version; do
                [ -z "$pkg_name" ] || [ -z "$version" ] && continue
                # O(1) lookups of the eco and wildcard namespaces
                check_vulnerability "npm" "$pkg_name" "$version" "$package_file" || true
            done <<< "$deps"

            # Check if vulnerabilities were found in this file
            local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
            if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
                echo -e "${GREEN}✓ [$package_file] No vulnerabilities found${NC}"
            fi
        done <<< "$PACKAGE_JSON_FILES"
    fi

    # Runtime versions the project targets (.nvmrc, Dockerfile, composer.json...)
    [ "$runtime_feed_loaded" = false ] || [ -z "$RUNTIME_FILES" ] || scan_runtimes

    [ "$go_reachability" = false ] || go_reachability

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}📊 SUMMARY${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ $FOUND_VULNERABLE -eq 0 ]; then
        echo -e "${GREEN}✅ No vulnerable packages detected${NC}"
    else
        # Count unique vulnerable packages (unique eco:name@version identities)
        local unique_vulns=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | awk -F'|' '{print $2":"$3}' | sort -u | wc -l | tr -d ' ')
        local total_occurrences=${#VULNERABLE_PACKAGES[@]}

        echo -e "${RED}⚠️  Found ${unique_vulns} vulnerable package(s) in ${total_occurrences} location(s)${NC}"
        echo ""

        # Group by package (group key = eco:name@version)
        declare -A pkg_files
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg_ver <<< "$vuln"
            local group_key="${eco}:${pkg_ver}"
            if [ -z "${pkg_files[$group_key]}" ]; then
                pkg_files[$group_key]="$file"
            else
                pkg_files[$group_key]="${pkg_files[$group_key]}|$file"
            fi
        done

        # Display grouped results
        for pkg in $(printf '%s\n' "${!pkg_files[@]}" | sort -u); do
            # Strip the ecosystem namespace for display (split at FIRST ':' only).
            # npm packages print with no prefix (byte-identical to legacy output);
            # other ecosystems get a "[eco] " label.
            local disp_eco="${pkg%%:*}"
            local disp_rest="${pkg#*:}"
            if [ "$disp_eco" = "npm" ]; then
                echo -e "${RED}   ⚠️  $disp_rest${NC}"
            else
                echo -e "${RED}   ⚠️  [$disp_eco] $disp_rest${NC}"
            fi

            IFS='|' read -ra files <<< "${pkg_files[$pkg]}"
            # Called in any location wins; "not called" needs every location.
            if [ ${#VULN_REACHABILITY[@]} -gt 0 ]; then
                local reach="not called"
                for file in "${files[@]}"; do
                    reachability_of "$file" "$pkg"
                    case "$REACHABILITY" in
                        called) reach=called; break ;;
                        "") reach="" ;;
                    esac
                done
                [ -z "$reach" ] || echo -e "      ${BLUE}Reachability: $reach (govulncheck)${NC}"
            fi
            print_advisories "${VULN_ADVISORIES[$pkg]:-}" && echo ""

            for file in "${files[@]}"; do
                echo -e "${YELLOW}      └─ $file${NC}"
            done
        done
        
        echo ""
        echo -e "${YELLOW}💡 Recommendations:${NC}"
        echo "   • Update vulnerable packages to patched versions"
        echo "   • Run your package manager's audit command for more details"

        # Create GitHub issues if requested
        if [ "$CREATE_GITHUB_ISSUE" = true ]; then
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -e "${BLUE}📝 Creating GitHub Issues (1 issue per package)${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            create_package_issues
        fi

        # Create a single consolidated GitHub issue per repository if requested
        if [ "$CREATE_SINGLE_ISSUE" = true ]; then
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -e "${BLUE}📝 Creating Single Consolidated GitHub Issue${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            create_consolidated_issues
        fi
    fi
    if [ ${#RUNTIME_WARNINGS[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  Runtime versions to review (warnings, not counted as findings):${NC}"
        local runtime_warning
        for runtime_warning in "${RUNTIME_WARNINGS[@]}"; do
            echo -e "${YELLOW}   • $runtime_warning${NC}"
        done
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Export results if requested (also when empty: see export_vulnerabilities_json)
    if [ -n "$export_json_file" ]; then
        echo ""
        export_vulnerabilities_json "$export_json_file" || exit "$EXIT_ERROR"
    fi

    if [ -n "$export_csv_file" ]; then
        echo ""
        export_vulnerabilities_csv "$export_csv_file" || exit "$EXIT_ERROR"
    fi

    # An unreadable project file makes a clean result incomplete.
    if [ "$FOUND_VULNERABLE" -eq 0 ] && [ "$UNREADABLE_FILE_COUNT" -gt 0 ]; then
        echo -e "${RED}❌ Scan incomplete: $UNREADABLE_FILE_COUNT project file(s) could not be read${NC}"
        exit "$EXIT_ERROR"
    fi
    exit $FOUND_VULNERABLE
}
# Run main function only when executed directly (allows `source script.sh` in unit tests)
if [[ "${BASH_SOURCE[0]:-}" == "$0" || -z "${BASH_SOURCE[0]:-}" ]]; then
    main "$@"
fi
