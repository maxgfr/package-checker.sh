#!/usr/bin/env bash
# GENERATED FILE NOTICE: script.sh is built from src/ by ./build.sh — edit src/, not script.sh.

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

set -e

# Version - automatically updated by release workflow
# Last release: https://github.com/maxgfr/package-checker.sh/releases
# NOTE: this exact 'VERSION="..."' format is sed-matched by .releaserc.json — do not reformat.
VERSION="1.11.6"

# Default configuration
CONFIG_FILE=".package-checker.config.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
VULN_DATA=""
DATA_SOURCES=()
FOUND_VULNERABLE=0
VULNERABLE_PACKAGES=()
CSV_COLUMNS=()

# Pre-built vulnerability lookup tables (for O(1) lookup)
declare -A VULN_EXACT_LOOKUP      # VULN_EXACT_LOOKUP[package]="ver1|ver2|..."
declare -A VULN_RANGE_LOOKUP      # VULN_RANGE_LOOKUP[package]="range1|range2|..."
declare -A VULN_METADATA_SEVERITY # VULN_METADATA_SEVERITY[package@version OR package]="critical|high|medium|low"
declare -A VULN_METADATA_GHSA     # VULN_METADATA_GHSA[package@version OR package]="GHSA-xxxx-xxxx-xxxx"
declare -A VULN_METADATA_CVE      # VULN_METADATA_CVE[package@version OR package]="CVE-YYYY-NNNNN"
declare -A VULN_METADATA_SOURCE   # VULN_METADATA_SOURCE[package@version OR package]="ghsa|osv|custom"
declare -A VULN_ADVISORIES        # VULN_ADVISORIES[package@version]="sev;ghsa;cve;src||sev;ghsa;cve;src" (all matching advisories)
declare -A VULN_PATCHED           # VULN_PATCHED[package:GHSA-xxx]="patched_version" (highest upper bound per GHSA)
declare -A VULN_METADATA_FIX      # VULN_METADATA_FIX[package:range]="fix_version" (upper bound from range)
VULN_LOOKUP_BUILT=false

# Configuration defaults (can be overridden by config file)
CONFIG_IGNORE_PATHS=("node_modules" ".yarn" ".git")
CONFIG_DEPENDENCY_TYPES=("dependencies" "devDependencies" "optionalDependencies")
CONFIG_ECOSYSTEMS=""  # optional feed-loading override from config (options.ecosystems)

# Ecosystem registry lookup tables — derived from ECOSYSTEM_REGISTRY by
# build_ecosystem_tables() (see src/50-ecosystems/01-registry.sh)
declare -A LOCKFILE_PARSER   # LOCKFILE_PARSER[basename]="analyze_fn"
declare -A LOCKFILE_ECO      # LOCKFILE_ECO[basename]="purl-type"
declare -A LOCKFILE_ALIAS    # LOCKFILE_ALIAS[basename]="type-alias"
KNOWN_LOCKFILE_ALIASES=""    # space-separated unique alias list (validation + help)

# Ecosystems detected in the scanned project (eco -> 1); drives default-feed loading
declare -A DETECTED_ECOSYSTEMS

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

# Get all keys from a JSON object
# Usage: json_keys "$json"
json_keys() {
    local json="$1"
    # Return only the top-level keys (children of the root object).
    # Use an awk-based parser that respects strings, escapes and nesting depth.
    echo "$json" | tr '\n' ' ' | awk '
    {
        s=$0
        depth=0
        in_str=0
        prev=""
        key=""
        collecting=0
        for(i=1;i<=length(s);i++){
            c=substr(s,i,1)
            if(in_str){
                if(c=="\"" && prev!="\\"){
                    in_str=0
                    # look ahead for next non-space char
                    j=i+1
                    nextc=""
                    while(j<=length(s)){
                        nc=substr(s,j,1)
                        if(nc ~ /[[:space:]]/){ j++; continue }
                        nextc=nc
                        break
                    }
                    if(nextc==":" && depth==1){ print key }
                    collecting=0
                    key=""
                } else {
                    if(collecting==1) key = key c
                }
            } else {
                if(c=="\""){
                    in_str=1
                    collecting=1
                    key=""
                } else if(c=="{"){
                    depth++
                } else if(c=="}"){
                    depth--
                }
            }
            prev=c
        }
    }' | sort -u
}

# Check if JSON object has a key
# Usage: json_has_key "$json" "key"
json_has_key() {
    local json="$1"
    local key="$2"
    local escaped_key=$(escape_regex "$key")
    if echo "$json" | grep -qE "\"$escaped_key\"[[:space:]]*:"; then
        return 0
    fi
    return 1
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

# Iterate over array elements (outputs one element per line)
# Usage: json_array_iterate "$json_array"
json_array_iterate() {
    local json="$1"
    local len=$(json_array_length "$json")
    local i=0
    while [ $i -lt $len ]; do
        local elem=$(json_array_get "$json" $i)
        # Remove quotes from string elements
        echo "$elem" | sed 's/^"//;s/"$//'
        i=$((i + 1))
    done
}

# Count keys in JSON object (object length)
# OPTIMIZED: Uses fast pattern matching instead of full JSON parsing
# Works for both compact and formatted JSON
# Usage: json_object_length "$json"
json_object_length() {
    local json="$1"
    # Fast method: count occurrences of "key": { pattern (with optional whitespace)
    # This works for both compact JSON ("key":{) and formatted JSON ("key": {)
    local count
    count=$(echo "$json" | tr -d '\n\r\t' | grep -oE '"[^"]+"\s*:\s*\{' | wc -l | tr -d ' ')
    echo "${count:-0}"
}

# Merge two JSON objects (simple merge, second overwrites first)
# Usage: json_merge "$json1" "$json2"
json_merge() {
    # Merge two top-level JSON objects (both expected as object strings)
    # - keys are merged
    # - when a key exists in both, try to merge their versions and versions_range arrays
    local json1="$1"
    local json2="$2"

    # Build a set of all top-level keys
    local keys1=$(json_keys "$json1")
    local keys2=$(json_keys "$json2")
    local all_keys="$(printf '%s\n%s' "$keys1" "$keys2" | sort -u)"

    local out="{"
    local first=true

    for key in $all_keys; do
        [ -z "$key" ] && continue

        # Extract object for this key from both inputs
        local obj1=$(json_get_object "$json1" "$key")
        local obj2=$(json_get_object "$json2" "$key")

        # Normalize empty objects
        [ -z "$obj1" ] && obj1='{}'
        [ -z "$obj2" ] && obj2='{}'

        local merged_obj=""

        # If one of objects is empty, take the other
        if [ "$obj1" = "{}" ] && [ "$obj2" = "{}" ]; then
            merged_obj="{}"
        elif [ "$obj1" = "{}" ]; then
            merged_obj="$obj2"
        elif [ "$obj2" = "{}" ]; then
            merged_obj="$obj1"
        else
            # Merge versions and ranges from both objects into unique arrays
            declare -A seen_versions
            declare -A seen_ranges
            local versions_list=()
            local ranges_list=()

            # Helper to add array items into set/array
            add_items() {
                local arr_json="$1"
                local kind="$2" # version|range
                # iterate elements
                local len=$(json_array_length "$arr_json")
                local i=0
                while [ $i -lt $len ]; do
                    local v=$(json_array_get "$arr_json" $i)
                    # Strip surrounding quotes if present
                    v=$(echo "$v" | sed 's/^"//;s/"$//')
                    if [ -n "$v" ]; then
                        if [ "$kind" = "version" ]; then
                            if [ -z "${seen_versions[$v]+x}" ]; then
                                seen_versions[$v]=1
                                versions_list+=("$v")
                            fi
                        else
                            if [ -z "${seen_ranges[$v]+x}" ]; then
                                seen_ranges[$v]=1
                                ranges_list+=("$v")
                            fi
                        fi
                    fi
                    i=$((i+1))
                done
            }

            # Extract arrays from objects if present
            local v1=$(json_get_array "$obj1" "versions")
            local v2=$(json_get_array "$obj2" "versions")
            local r1=$(json_get_array "$obj1" "versions_range")
            local r2=$(json_get_array "$obj2" "versions_range")

            add_items "$v1" "version"
            add_items "$v2" "version"
            add_items "$r1" "range"
            add_items "$r2" "range"

            # Build merged object JSON
            merged_obj="{"
            local has=false
            if [ ${#versions_list[@]} -gt 0 ]; then
                merged_obj+="\"versions\":["
                local firstv=true
                for vv in "${versions_list[@]}"; do
                    if [ "$firstv" = false ]; then merged_obj+=","; fi
                    firstv=false
                    merged_obj+="\"${vv}\""
                done
                merged_obj+="]"
                has=true
            fi
            if [ ${#ranges_list[@]} -gt 0 ]; then
                if [ "$has" = true ]; then merged_obj+=","; fi
                merged_obj+="\"versions_range\":["
                local firstr=true
                for rr in "${ranges_list[@]}"; do
                    if [ "$firstr" = false ]; then merged_obj+=","; fi
                    firstr=false
                    merged_obj+="\"${rr}\""
                done
                merged_obj+="]"
            fi
            merged_obj+="}"
        fi

        # Append to output
        if [ "$first" = true ]; then
            out+="\"${key}\":${merged_obj}"
            first=false
        else
            out+=",\"${key}\":${merged_obj}"
        fi
    done

    out+="}"
    echo "$out"
}

# ============================================================================
# End of JSON Parser Functions
# ============================================================================

# Show version information
show_version() {
    echo "package-checker.sh version $VERSION"
    echo ""
    echo "A tool to check Node.js projects for vulnerable packages against custom data sources."
    echo "Repository: https://github.com/maxgfr/package-checker.sh"
    exit 0
}

# Help message
show_help() {
    cat << EOF
Usage: $0 [PATH] [OPTIONS]

A tool to check Node.js projects for vulnerable packages against custom data sources.

ARGUMENTS:
    PATH                    Directory to scan (default: current directory)

OPTIONS:
    -h, --help              Show this help message
    --help-ai               Show AI help menu
    --help-ai prompt        Output the AI system prompt (prompt.md)
    --help-ai doc           Output the full AI guide (docs/ai-guide.md)
    -v, --version           Show version information
    -s, --source SOURCE     Data source path or URL (can be used multiple times)
    --default-source-ghsa   Use default GHSA source (auto-detect from brew, ./data/, /app/data/, or GitHub)
    --default-source-osv    Use default OSV source (auto-detect from brew, ./data/, /app/data/, or GitHub)
    --default-source-ghsa-osv        Use both default GHSA and OSV sources (recommended)
    -f, --format FORMAT     Data format: json, csv, purl, sarif, sbom-cyclonedx, or trivy-json (default: json)
    -c, --config FILE       Path to configuration file (default: .package-checker.config.json)
    --no-config             Skip loading configuration file
    --csv-columns COLS      CSV columns specification (e.g., "1,2" or "name,versions")
    --package-name NAME     Check vulnerability for a specific package name
    --package-version VER   Check specific version (requires --package-name)
    --ecosystem ECO         Ecosystem for --package-name (default: npm). One of:
                            npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions
    --export-json FILE      Export vulnerability results to JSON file (default: vulnerabilities.json)
    --export-csv FILE       Export vulnerability results to CSV file (default: vulnerabilities.csv)
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

EXAMPLES:
    # Scan current directory with default sources (recommended)
    $0 --default-source

    # Scan specific directory
    $0 ./my-project --default-source-osv
    $0 /absolute/path/to/project --default-source-ghsa-osv

    # Use configuration file
    $0 --config .package-checker.config.json

    # Use custom source
    $0 --source https://example.com/vulns.json

    # GitHub organization scan
    $0 --github-org myorg --github-token ghp_xxxx --default-source-ghsa-osv

    # Check specific package
    $0 --package-name express --package-version 4.17.1

    # Fetch vulnerability feeds (all ecosystems)
    $0 --fetch-all data

    # Fetch feeds for specific ecosystems only
    $0 --fetch-osv pypi,golang
    $0 --fetch-ghsa cargo

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
    "dependency_types": ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
  }
}

DATA FORMATS:

JSON format (object with package names as keys):
{
  "package-name": {
    "versions": ["1.0.0", "2.0.0"]
  }
}

CSV format (default: package,version):
package-name,1.0.0
package-name,2.0.0
another-package,3.0.0

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
    content=$(curl -fsSL "$url" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$content" ]; then
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
            content=$(resolve_ai_doc "prompt.md")
            if [ $? -eq 0 ]; then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load prompt.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/prompt.md"
            fi
            ;;
        doc)
            echo -e "${BLUE}package-checker.sh — AI Guide (Full Reference)${NC}"
            echo -e "${BLUE}================================================${NC}"
            echo ""
            echo -e "${YELLOW}Source: ${GITHUB_RAW_BASE}/docs/ai-guide.md${NC}"
            echo ""
            local content
            content=$(resolve_ai_doc "docs/ai-guide.md")
            if [ $? -eq 0 ]; then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load docs/ai-guide.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/docs/ai-guide.md"
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

# Check that curl is installed
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        echo "❌ Error: 'curl' must be installed to run this script"
        exit 1
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

# Make a GitHub API request with automatic retry on rate limit
github_request() {
    local url="$1"
    local max_retries=3
    local retry_delay=60
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        local response
        local http_code
        
        response=$(curl -sS -w "\n%{http_code}" \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: package-checker-script" \
            "$url")
        
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')
        
        if [ "$http_code" = "200" ]; then
            echo "$response"
            return 0
        fi
        
        # Handle rate limiting (403 or 429)
        if [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
            if [ $attempt -lt $max_retries ]; then
                # Check for Retry-After header or rate limit reset time
                local wait_time=$retry_delay
                if echo "$response" | grep -q "rate limit"; then
                    echo -e "${YELLOW}⚠️  Rate limit hit, waiting ${wait_time}s before retry ($attempt/$max_retries)...${NC}" >&2
                    sleep $wait_time
                    attempt=$((attempt + 1))
                    continue
                fi
            fi
        fi
        
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
    
    # Get the default branch first
    local repo_info
    repo_info=$(github_request "https://api.github.com/repos/${repo_full_name}") || return 1
    local default_branch=$(json_get_value "$repo_info" "default_branch")
    
    # Get the full tree recursively
    local tree_url="https://api.github.com/repos/${repo_full_name}/git/trees/${default_branch}?recursive=1"
    local tree_response
    tree_response=$(github_request "$tree_url") || return 1
    
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
        grep -E "(${scan_regex})\$")
    
    if [ -z "$target_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Count files by type
    local pkg_count=$(echo "$target_files" | grep -c "package.json" || echo "0")
    local lock_count=$(echo "$target_files" | grep -v "package.json" | grep -c "." || echo "0")
    echo "   Found $pkg_count package.json file(s) and $lock_count lockfile(s)"
    
    # Create repo directory
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    mkdir -p "$repo_dir"
    
    # Fetch each file
    while IFS= read -r file_path; do
        [ -z "$file_path" ] && continue
        
        local raw_url="https://raw.githubusercontent.com/${repo_full_name}/${default_branch}/${file_path}"
        local file_content
        file_content=$(curl -sS \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "User-Agent: package-checker-script" \
            "$raw_url")
        
        # Save the file
        local full_path="${repo_dir}/${file_path}"
        local dir=$(dirname "$full_path")
        mkdir -p "$dir"
        
        echo "$file_content" > "$full_path"
        
        local file_name=$(basename "$file_path")
        if [ "$file_name" = "package.json" ]; then
            echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
        else
            echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
        fi
    done <<< "$target_files"
}

# Search for package.json and lockfiles in a repository using Search API (requires token)
search_package_json_in_repo() {
    local repo_full_name="$1"
    local repo_name="$2"
    
    echo -e "   ${BLUE}Searching for package.json and lockfiles...${NC}"
    
    # Search for multiple file types (derived from the ecosystem registry)
    local all_files=""
    local search_terms=() _term
    for _term in $(ecosystem_scan_filenames); do
        search_terms+=("$_term")
    done
    
    for term in "${search_terms[@]}"; do
        local search_url="https://api.github.com/search/code?q=filename:${term}+repo:${repo_full_name}"
        local search_results
        
        search_results=$(github_request "$search_url") 2>/dev/null || continue
        
        # OPTIMIZED: Extract path and url pairs using grep/sed instead of slow JSON parsing
        # Format: path|url (one per line)
        local file_pairs
        file_pairs=$(echo "$search_results" | tr '\n' ' ' | \
            grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"[^}]*"url"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"[^}]*"url"[[:space:]]*:[[:space:]]*"/|/;s/"$//')
        
        if [ -n "$file_pairs" ]; then
            if [ -z "$all_files" ]; then
                all_files="$file_pairs"
            else
                all_files="$all_files"$'\n'"$file_pairs"
            fi
        fi
        
        sleep 1  # Rate limiting between searches
    done
    
    if [ -z "$all_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Remove duplicates and count
    all_files=$(echo "$all_files" | sort -u)
    local count=$(echo "$all_files" | wc -l | tr -d ' ')
    echo "   Found $count file(s)"
    
    # Create repo directory
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    mkdir -p "$repo_dir"
    
    # Fetch each file
    while IFS='|' read -r file_path file_url; do
        [ -z "$file_path" ] && continue
        
        # Get file content
        local content_response
        content_response=$(github_request "$file_url") || continue
        
        local download_url=$(json_get_value "$content_response" "download_url")
        
        if [ -n "$download_url" ] && [ "$download_url" != "null" ]; then
            local file_content
            file_content=$(curl -sS \
                ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
                -H "User-Agent: package-checker-script" \
                "$download_url")
            
            # Save the file
            local full_path="${repo_dir}/${file_path}"
            local dir=$(dirname "$full_path")
            mkdir -p "$dir"
            
            echo "$file_content" > "$full_path"
            
            local file_name=$(basename "$file_path")
            if [ "$file_name" = "package.json" ]; then
                echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
            else
                echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
            fi
        fi
        
        sleep 1  # Rate limiting
    done <<< "$all_files"
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
    response=$(curl -s -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "$json_payload" \
        "https://api.github.com/repos/${repo_full_name}/issues" 2>&1)

    # Check if issue was created successfully
    if echo "$response" | grep -q '"html_url"'; then
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
    
    # Token is required for organization (uses Search API)
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
            
            # Use Tree API instead of Search API (much higher rate limit)
            search_package_json_in_repo_tree "$repo_full_name" "$repo_name"
            
            sleep "$GITHUB_RATE_LIMIT_DELAY"
        done <<< "$repos"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ GitHub packages fetched to: $(realpath "$GITHUB_OUTPUT_DIR")${NC}"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# Check if a version string is a range (contains operators like >=, <=, >, <)
is_version_range() {
    local version="$1"
    if [[ "$version" =~ (>=|<=|>|<) ]]; then
        return 0  # true - it's a range
    fi
    return 1  # false - it's an exact version
}

# FAST CSV Parser using awk - parses entire CSV in a single pass
# Handles: quoted fields, multi-line values, Windows line endings, version ranges
# Output: JSON object with versions and versions_range arrays
parse_csv_to_json() {
    local csv_data="$1"
    local col1="${CSV_COLUMNS[0]:-}"
    local col2="${CSV_COLUMNS[1]:-}"
    
    # Use awk for fast single-pass parsing
    echo "$csv_data" | tr -d '\r' | awk -v col1="$col1" -v col2="$col2" '
    BEGIN {
        FS = ","
        pkg_col = 1
        ver_col = 2
        header_done = 0
        pkg_count = 0
    }
    
    # Function to check if a string is a version range
    function is_range(v) {
        return (v ~ />/ || v ~ /</)
    }
    
    # Function to trim whitespace and quotes
    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }
    
    # Function to parse a CSV line handling quoted fields
    # Returns fields in array f[], returns field count
    function parse_csv_line(line, f,    i, j, n, in_quote, field, c) {
        n = 1
        field = ""
        in_quote = 0
        
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            
            if (c == "\"") {
                # Check for escaped quote (double quote)
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
        # Last field
        f[n] = trim(field)
        return n
    }
    
    # Handle multi-line quoted values by accumulating lines
    {
        # Accumulate line if we are in the middle of a quoted field
        if (pending_line != "") {
            current_line = pending_line " " $0
            pending_line = ""
        } else {
            current_line = $0
        }
        
        # Count quotes to check if line is complete
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            # Odd number of quotes - line continues
            pending_line = current_line
            next
        }
        
        # Skip empty lines
        if (current_line == "") next
        
        # Parse the line
        field_count = parse_csv_line(current_line, fields)
        
        # First non-empty line is header
        if (!header_done) {
            header_done = 1
            
            # Try to find column indices from header names if column names specified
            if (col1 != "" && col2 != "") {
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    lower_col1 = tolower(col1)
                    lower_col2 = tolower(col2)
                    
                    if (lower_field == lower_col1) pkg_col = i
                    if (lower_field == lower_col2) ver_col = i
                }
            } else if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
                # Numeric column indices
                pkg_col = int(col1)
                ver_col = int(col2)
            }
            
            # Skip header row
            next
        }
        
        # Extract package and version
        pkg = fields[pkg_col]
        ver = fields[ver_col]
        
        # Skip invalid entries
        if (pkg == "" || ver == "") next
        if (tolower(pkg) == "package" || tolower(pkg) == "name") next
        
        # Track package order (first occurrence)
        if (!(pkg in pkg_seen)) {
            pkg_seen[pkg] = 1
            pkg_order[++pkg_count] = pkg
        }
        
        # Categorize as version or range
        if (is_range(ver)) {
            if (pkg in pkg_ranges) {
                pkg_ranges[pkg] = pkg_ranges[pkg] ",\"" ver "\""
            } else {
                pkg_ranges[pkg] = "\"" ver "\""
            }
        } else {
            if (pkg in pkg_versions) {
                pkg_versions[pkg] = pkg_versions[pkg] ",\"" ver "\""
            } else {
                pkg_versions[pkg] = "\"" ver "\""
            }
        }
    }
    
    END {
        # Build JSON output
        printf "{"
        first = 1
        
        for (i = 1; i <= pkg_count; i++) {
            pkg = pkg_order[i]
            
            if (!first) printf ","
            first = 0
            
            printf "\"%s\":{", pkg
            has_content = 0
            
            if (pkg in pkg_versions) {
                printf "\"versions\":[%s]", pkg_versions[pkg]
                has_content = 1
            }
            
            if (pkg in pkg_ranges) {
                if (has_content) printf ","
                printf "\"versions_range\":[%s]", pkg_ranges[pkg]
            }
            
            printf "}"
        }
        
        printf "}"
    }
    '
}

# FAST CSV Parser that generates lookup table eval commands directly
# This bypasses the slow JSON intermediate step for large CSV files
# Returns: bash eval commands to populate VULN_EXACT_LOOKUP and VULN_RANGE_LOOKUP
parse_csv_to_lookup_eval() {
    local csv_data="$1"
    local col1="${CSV_COLUMNS[0]:-}"
    local col2="${CSV_COLUMNS[1]:-}"
    
    # Use awk to parse CSV and generate eval commands directly
    echo "$csv_data" | tr -d '\r' | awk -v col1="$col1" -v col2="$col2" '
    BEGIN {
        FS = ","
        pkg_col = 1
        ver_col = 2
        header_done = 0
        pkg_count = 0
    }
    
    function is_range(v) {
        return (v ~ />/ || v ~ /</)
    }
    
    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }
    
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
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
        
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            pending_line = current_line
            next
        }
        
        if (current_line == "") next
        
        field_count = parse_csv_line(current_line, fields)
        
        if (!header_done) {
            header_done = 1
            
            if (col1 != "" && col2 != "") {
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    if (lower_field == tolower(col1)) pkg_col = i
                    if (lower_field == tolower(col2)) ver_col = i
                }
            } else if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
                pkg_col = int(col1)
                ver_col = int(col2)
            }
            next
        }
        
        pkg = fields[pkg_col]
        ver = fields[ver_col]
        
        if (pkg == "" || ver == "") next
        if (tolower(pkg) == "package" || tolower(pkg) == "name") next
        
        if (!(pkg in pkg_seen)) {
            pkg_seen[pkg] = 1
            pkg_order[++pkg_count] = pkg
        }
        
        if (is_range(ver)) {
            if (pkg in pkg_ranges) {
                pkg_ranges[pkg] = pkg_ranges[pkg] "|" ver
            } else {
                pkg_ranges[pkg] = ver
            }
        } else {
            if (pkg in pkg_versions) {
                pkg_versions[pkg] = pkg_versions[pkg] "|" ver
            } else {
                pkg_versions[pkg] = ver
            }
        }
    }
    
    END {
        # OPTIMIZED: Output package count FIRST (allows read without grep)
        printf "CSV_PKG_COUNT=%d\n", pkg_count

        # CSV carries no ecosystem info -> wildcard namespace "*:"
        # Output eval commands that MERGE with existing data instead of overwriting
        for (pkg in pkg_versions) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(pkg_versions[pkg]), escape_sq(nk), escape_sq(pkg_versions[pkg])
        }
        for (pkg in pkg_ranges) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(pkg_ranges[pkg]), escape_sq(nk), escape_sq(pkg_ranges[pkg])
        }
    }
    '
}

# Alias for backward compatibility
parse_csv_default() {
    parse_csv_to_json "$1"
}

# Parse PURL format to lookup tables
# PURL format: pkg:type/namespace/name@version
# Example: pkg:npm/lodash@4.17.21
# Example with version range: pkg:npm/express@>=4.0.0 <4.17.0
parse_purl_to_lookup_eval() {
    local raw_data="$1"

    # OPTIMIZED: Use awk to parse PURL lines and generate eval commands
    # Key optimizations:
    # 1. Batch all versions/ranges per package before output (reduces eval overhead)
    # 2. Output count first to avoid grep post-processing
    # 3. Use printf for efficient output
    printf '%s\n' "$raw_data" | awk '
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }

    # Compare two semver versions numerically (ignoring pre-release suffixes)
    # Returns: 1 if v1>v2, -1 if v1<v2, 0 if equal
    function compare_vers(v1, v2,   a, b, na, nb, i, max, pa, pb) {
        # Strip pre-release suffix for comparison
        sub(/-.*/, "", v1)
        sub(/-.*/, "", v2)
        na = split(v1, a, ".")
        nb = split(v2, b, ".")
        max = (na > nb) ? na : nb
        for (i = 1; i <= max; i++) {
            pa = (i <= na) ? a[i] + 0 : 0
            pb = (i <= nb) ? b[i] + 0 : 0
            if (pa > pb) return 1
            if (pa < pb) return -1
        }
        return 0
    }

    function parse_query_params(query_string, params) {
        delete params
        if (query_string == "") return

        # Split by & to get individual parameters
        n = split(query_string, pairs, "&")
        for (i = 1; i <= n; i++) {
            if (index(pairs[i], "=") > 0) {
                split(pairs[i], kv, "=")
                params[kv[1]] = kv[2]
            }
        }
    }

    # Canonicalize a package name for a given purl type (ecosystem).
    # "name" is the full path (already percent-decoded) between the first "/" and "@".
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
            sub(/^https?:\/\//, "", lo)
            sub(/\.git$/, "", lo)
            return tolower(lo)
        }
        # npm, golang, cargo, gem, pub, hex and unknown types: name as-is
        return name
    }

    BEGIN {
        pkg_count = 0
    }

    # Skip empty lines and comments
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }

    {
        line = $0
        # Remove leading/trailing whitespace
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        # Parse PURL: pkg:type/namespace/name@version?params or pkg:type/name@version?params
        if (match(line, /^pkg:[^\/]+\/(.+)@(.+)$/)) {
            # Extract the purl type: text between "pkg:" and the first "/"
            type_end = index(line, "/")
            purl_type = substr(line, 5, type_end - 5)
            if (type_end > 0) {
                # Split the query string off FIRST — it may itself contain "@"
                main_part = line
                query_string = ""
                query_pos = index(line, "?")
                if (query_pos > 0) {
                    main_part = substr(line, 1, query_pos - 1)
                    query_string = substr(line, query_pos + 1)
                }

                # Split name/version at the LAST "@" of the pre-query part.
                # Versions/ranges never contain "@"; scoped names start with "@".
                at_pos = 0
                for (scan_i = length(main_part); scan_i > type_end; scan_i--) {
                    if (substr(main_part, scan_i, 1) == "@") { at_pos = scan_i; break }
                }
                if (at_pos > type_end) {
                    # Package name is the FULL path (all components between the
                    # first "/" and the last "@"), e.g. "@babel/traverse".
                    path = substr(main_part, type_end + 1, at_pos - type_end - 1)
                    # Version/range is everything after the last "@"
                    version = substr(main_part, at_pos + 1)

                    # Remove quotes if present
                    gsub(/"/, "", path)
                    gsub(/"/, "", version)

                    # Percent-decode common PURL encodings (%40 -> @, %2F -> /)
                    gsub(/%40/, "@", path)
                    gsub(/%2[fF]/, "/", path)

                    pkg_name = path

                    # Namespaced lookup key: "eco:name" (eco = purl type, name canonicalized)
                    canon_key = purl_type ":" canon_purl_name(purl_type, pkg_name)

                    # Parse query parameters
                    parse_query_params(query_string, params)

                    if (pkg_name != "" && version != "") {
                        # Detect if version is a range (contains space or operators)
                        # But exclude ? from the check as it is now used for params
                        is_range = (version ~ /[[:space:]]|>|<|\^|~|\*|\|\|/)

                        # Create unique key for metadata, namespaced by ecosystem
                        # For ranges: use eco:name:range to avoid collision when multiple advisories affect the same package
                        # For exact versions: use eco:name@version
                        if (is_range) {
                            meta_key = canon_key ":" version
                        } else {
                            meta_key = canon_key "@" version
                        }

                        # Store metadata if present
                        if ("severity" in params) {
                            pkg_severity[meta_key] = params["severity"]
                        }
                        if ("ghsa" in params) {
                            pkg_ghsa[meta_key] = params["ghsa"]
                        }
                        if ("cve" in params) {
                            pkg_cve[meta_key] = params["cve"]
                        }
                        if ("source" in params) {
                            pkg_source[meta_key] = params["source"]
                        }

                        # Extract fix version from range upper bound and track patched versions
                        if (is_range) {
                            if (match(version, /<[0-9]/)) {
                                # Extract upper bound: last <X.Y.Z part
                                n_parts = split(version, range_parts, "<")
                                if (n_parts >= 2) {
                                    upper = range_parts[n_parts]
                                    gsub(/^[=[:space:]]+/, "", upper)
                                    gsub(/[[:space:]]+$/, "", upper)
                                    # Store fix version per advisory
                                    pkg_fix[meta_key] = upper
                                    # Track patched versions for GHSA false positive detection
                                    if ("ghsa" in params) {
                                        patched_key = canon_key ":" params["ghsa"]
                                        if (!(patched_key in pkg_patched) || compare_vers(upper, pkg_patched[patched_key]) > 0) {
                                            pkg_patched[patched_key] = upper
                                        }
                                    }
                                }
                            }
                        }

                        if (is_range) {
                            # Version range (keyed by namespaced eco:name)
                            if (canon_key in pkg_ranges) {
                                pkg_ranges[canon_key] = pkg_ranges[canon_key] "|" version
                            } else {
                                pkg_ranges[canon_key] = version
                                pkg_count++
                            }
                        } else {
                            # Exact version (keyed by namespaced eco:name)
                            if (canon_key in pkg_versions) {
                                pkg_versions[canon_key] = pkg_versions[canon_key] "|" version
                            } else {
                                pkg_versions[canon_key] = version
                                pkg_count++
                            }
                        }
                    }
                }
            }
        }
    }

    END {
        # OPTIMIZED: Output unique package count FIRST (allows read without grep)
        delete unique_pkgs
        for (pkg in pkg_versions) unique_pkgs[pkg] = 1
        for (pkg in pkg_ranges) unique_pkgs[pkg] = 1
        unique_count = 0
        for (pkg in unique_pkgs) unique_count++
        printf "PURL_PKG_COUNT=%d\n", unique_count

        # Output eval commands for exact versions
        for (pkg in pkg_versions) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_versions[pkg]), escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
        # Output eval commands for version ranges
        for (pkg in pkg_ranges) {
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_ranges[pkg]), escape_sq(pkg), escape_sq(pkg_ranges[pkg])
        }

        # Output eval commands for patched versions (highest upper bound per package:GHSA)
        for (key in pkg_patched) {
            printf "VULN_PATCHED['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_patched[key])
        }

        # Output eval commands for metadata
        for (key in pkg_severity) {
            printf "VULN_METADATA_SEVERITY['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_severity[key])
        }
        for (key in pkg_ghsa) {
            printf "VULN_METADATA_GHSA['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_ghsa[key])
        }
        for (key in pkg_cve) {
            printf "VULN_METADATA_CVE['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_cve[key])
        }
        for (key in pkg_source) {
            printf "VULN_METADATA_SOURCE['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_source[key])
        }
        for (key in pkg_fix) {
            printf "VULN_METADATA_FIX['\''%s'\'']='\''%s'\''\n", escape_sq(key), escape_sq(pkg_fix[key])
        }
    }
    '
}

# Parse SARIF format to lookup tables
# SARIF format: Static Analysis Results Interchange Format
# Example: Generated by Trivy, Semgrep, etc.
parse_sarif_to_lookup_eval() {
    local raw_data="$1"

    # Use awk to parse SARIF JSON and extract vulnerabilities
    echo "$raw_data" | awk '
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }

    BEGIN {
        pkg_count = 0
        in_results = 0
        in_result = 0
        depth = 0
        current_pkg = ""
        current_version = ""
    }

    {
        # Look for "results": [ array
        if ($0 ~ /"results"[[:space:]]*:[[:space:]]*\[/) {
            in_results = 1
            next
        }

        if (in_results) {
            # Track depth to find result objects
            if ($0 ~ /\{/) depth++
            if ($0 ~ /\}/) depth--

            # Extract package name from message text
            # Format: "text": "package-lock.json: next@16.0.4"
            if ($0 ~ /"text"[[:space:]]*:/) {
                text_line = $0
                sub(/.*"text"[[:space:]]*:[[:space:]]*"/, "", text_line)
                sub(/".*/, "", text_line)

                # Check if it contains package@version pattern
                if (text_line ~ /:[[:space:]]*[^:]+@[^[:space:]]+/) {
                    # Extract package@version after the colon
                    pkg_ver = text_line
                    sub(/.*:[[:space:]]*/, "", pkg_ver)

                    if (pkg_ver ~ /@/) {
                        split(pkg_ver, parts, "@")
                        if (parts[1] != "" && parts[2] != "") {
                            if (!(parts[1] in pkg_versions)) {
                                pkg_versions[parts[1]] = parts[2]
                                pkg_count++
                            } else {
                                if (pkg_versions[parts[1]] !~ parts[2]) {
                                    pkg_versions[parts[1]] = pkg_versions[parts[1]] "|" parts[2]
                                }
                            }
                        }
                    }
                }
            }

            if (depth == 0) in_results = 0
        }
    }

    END {
        # OPTIMIZED: Output package count FIRST (allows read without grep)
        printf "SARIF_PKG_COUNT=%d\n", pkg_count

        # SARIF carries no ecosystem info -> wildcard namespace "*:"
        # Output eval commands for exact versions
        for (pkg in pkg_versions) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(pkg_versions[pkg]), escape_sq(nk), escape_sq(pkg_versions[pkg])
        }
    }
    '
}

# Parse SBOM CycloneDX format to lookup tables
# SBOM format: Software Bill of Materials in CycloneDX JSON format
# Example: Generated by Trivy, Syft, etc.
parse_sbom_to_lookup_eval() {
    local raw_data="$1"

    # Use awk to parse SBOM JSON and extract vulnerabilities
    echo "$raw_data" | awk '
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }

    # Canonicalize a package name for a given purl type (ecosystem).
    function canon_purl_name(eco, name,   lo, cnt, parts) {
        if (eco == "pypi") {
            lo = tolower(name)
            gsub(/[-_.]+/, "-", lo)
            return lo
        } else if (eco == "maven") {
            if (index(name, ":") > 0) return name
            cnt = split(name, parts, "/")
            if (cnt >= 2) return parts[cnt-1] ":" parts[cnt]
            return name
        } else if (eco == "composer" || eco == "githubactions" || eco == "nuget") {
            return tolower(name)
        } else if (eco == "swift") {
            lo = name
            sub(/^https?:\/\//, "", lo)
            sub(/\.git$/, "", lo)
            return tolower(lo)
        }
        return name
    }

    BEGIN {
        pkg_count = 0
        in_vulnerabilities = 0
        depth = 0
        current_pkg = ""
        current_version = ""
    }

    {
        # Look for "vulnerabilities": [ array
        if ($0 ~ /"vulnerabilities"[[:space:]]*:[[:space:]]*\[/) {
            in_vulnerabilities = 1
            next
        }

        if (in_vulnerabilities) {
            # Track depth
            if ($0 ~ /\{/) depth++
            if ($0 ~ /\}/) depth--

            # Look for affects array within vulnerability
            if ($0 ~ /"affects"[[:space:]]*:[[:space:]]*\[/) {
                in_affects = 1
            }

            if ($0 ~ /"ref"[[:space:]]*:/) {
                # Extract package ref: "pkg:npm/package@version"
                ref = $0
                sub(/.*"ref"[[:space:]]*:[[:space:]]*"/, "", ref)
                sub(/".*/, "", ref)

                # Only PURL refs carry package info (skip CycloneDX bom-ref UUIDs)
                if (ref ~ /^pkg:[^\/]+\//) {
                    # Split query string off first (it may contain "@")
                    sbom_main = ref
                    sbom_qp = index(ref, "?")
                    if (sbom_qp > 0) sbom_main = substr(ref, 1, sbom_qp - 1)

                    sbom_te = index(sbom_main, "/")
                    sbom_eco = substr(sbom_main, 5, sbom_te - 5)

                    # Split name/version at the LAST "@"
                    sbom_ap = 0
                    for (sbom_i = length(sbom_main); sbom_i > sbom_te; sbom_i--) {
                        if (substr(sbom_main, sbom_i, 1) == "@") { sbom_ap = sbom_i; break }
                    }
                    if (sbom_ap > sbom_te) {
                        sbom_path = substr(sbom_main, sbom_te + 1, sbom_ap - sbom_te - 1)
                        current_version = substr(sbom_main, sbom_ap + 1)
                        gsub(/%40/, "@", sbom_path)
                        gsub(/%2[fF]/, "/", sbom_path)
                        # Namespaced lookup key: "eco:name"
                        current_pkg = sbom_eco ":" canon_purl_name(sbom_eco, sbom_path)
                    }
                }

                if (current_pkg != "" && current_version != "") {
                    if (!(current_pkg in pkg_versions)) {
                        pkg_versions[current_pkg] = current_version
                        pkg_count++
                    } else {
                        if (pkg_versions[current_pkg] !~ current_version) {
                            pkg_versions[current_pkg] = pkg_versions[current_pkg] "|" current_version
                        }
                    }
                    current_pkg = ""
                    current_version = ""
                }
            }

            if (depth == 0) in_vulnerabilities = 0
        }
    }

    END {
        # OPTIMIZED: Output package count FIRST (allows read without grep)
        printf "SBOM_PKG_COUNT=%d\n", pkg_count

        # Output eval commands for exact versions
        for (pkg in pkg_versions) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_versions[pkg]), escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
    }
    '
}

# Parse Trivy JSON format to lookup tables
# Trivy format: Trivy JSON output from filesystem or container scans
# Example: trivy fs --format json --output trivy-report.json .
parse_trivy_to_lookup_eval() {
    local raw_data="$1"

    # Use awk to parse Trivy JSON and extract vulnerabilities
    echo "$raw_data" | awk '
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }

    # Canonicalize a package name for a given purl type (ecosystem).
    function canon_purl_name(eco, name,   lo, cnt, parts) {
        if (eco == "pypi") {
            lo = tolower(name)
            gsub(/[-_.]+/, "-", lo)
            return lo
        } else if (eco == "maven") {
            if (index(name, ":") > 0) return name
            cnt = split(name, parts, "/")
            if (cnt >= 2) return parts[cnt-1] ":" parts[cnt]
            return name
        } else if (eco == "composer" || eco == "githubactions" || eco == "nuget") {
            return tolower(name)
        } else if (eco == "swift") {
            lo = name
            sub(/^https?:\/\//, "", lo)
            sub(/\.git$/, "", lo)
            return tolower(lo)
        }
        return name
    }

    # Build a namespaced key ("eco:name") from a purl string, or "" if not a purl
    function purl_to_key(purl,   pmain, pqp, pte, peco, pap, pi, ppath) {
        if (purl !~ /^pkg:[^\/]+\//) return ""
        pmain = purl
        pqp = index(purl, "?")
        if (pqp > 0) pmain = substr(purl, 1, pqp - 1)
        pte = index(pmain, "/")
        peco = substr(pmain, 5, pte - 5)
        pap = 0
        for (pi = length(pmain); pi > pte; pi--) {
            if (substr(pmain, pi, 1) == "@") { pap = pi; break }
        }
        if (pap <= pte) return ""
        ppath = substr(pmain, pte + 1, pap - pte - 1)
        gsub(/%40/, "@", ppath)
        gsub(/%2[fF]/, "/", ppath)
        return peco ":" canon_purl_name(peco, ppath)
    }

    BEGIN {
        pkg_count = 0
        in_results = 0
        in_vulnerabilities = 0
        depth = 0
        current_pkg = ""
        current_version = ""
        current_purl_key = ""
    }

    {
        # Look for "Results": [ array
        if ($0 ~ /"Results"[[:space:]]*:[[:space:]]*\[/) {
            in_results = 1
            next
        }

        if (in_results) {
            # Track depth
            if ($0 ~ /\{/) depth++
            if ($0 ~ /\}/) depth--

            # Look for "Vulnerabilities": [ array within Results
            if ($0 ~ /"Vulnerabilities"[[:space:]]*:[[:space:]]*\[/) {
                in_vulnerabilities = 1
            }

            if (in_vulnerabilities) {
                # Extract PkgName
                if ($0 ~ /"PkgName"[[:space:]]*:/) {
                    pkg = $0
                    sub(/.*"PkgName"[[:space:]]*:[[:space:]]*"/, "", pkg)
                    sub(/".*/, "", pkg)
                    if (pkg != "") current_pkg = pkg
                }

                # Extract PkgIdentifier.PURL (preferred: carries ecosystem)
                if ($0 ~ /"PURL"[[:space:]]*:/) {
                    purl = $0
                    sub(/.*"PURL"[[:space:]]*:[[:space:]]*"/, "", purl)
                    sub(/".*/, "", purl)
                    if (purl != "") current_purl_key = purl_to_key(purl)
                }

                # Extract InstalledVersion
                if ($0 ~ /"InstalledVersion"[[:space:]]*:/) {
                    ver = $0
                    sub(/.*"InstalledVersion"[[:space:]]*:[[:space:]]*"/, "", ver)
                    sub(/".*/, "", ver)
                    if (ver != "") current_version = ver
                }

                # When we close a vulnerability object and have both pkg and version
                if ($0 ~ /\}/ && current_pkg != "" && current_version != "") {
                    # Use the PURL-derived namespaced key when available; otherwise
                    # this result has no ecosystem info -> wildcard namespace "*:"
                    if (current_purl_key != "") {
                        store_key = current_purl_key
                    } else {
                        store_key = "*:" current_pkg
                    }
                    if (!(store_key in pkg_versions)) {
                        pkg_versions[store_key] = current_version
                        pkg_count++
                    } else {
                        if (pkg_versions[store_key] !~ current_version) {
                            pkg_versions[store_key] = pkg_versions[store_key] "|" current_version
                        }
                    }
                    current_pkg = ""
                    current_version = ""
                    current_purl_key = ""
                }
            }

            if (depth == 0) {
                in_results = 0
                in_vulnerabilities = 0
            }
        }
    }

    END {
        # OPTIMIZED: Output package count FIRST (allows read without grep)
        printf "TRIVY_PKG_COUNT=%d\n", pkg_count

        # Output eval commands for exact versions
        for (pkg in pkg_versions) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_versions[pkg]), escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
    }
    '
}

# Detect format from URL
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
    
    # Download or read local data
    local raw_data
    if [[ "$url" =~ ^https?:// ]] || [[ "$url" =~ ^ftp:// ]]; then
        # Remote URL - use curl
        if ! raw_data=$(curl -sS "$url"); then
            echo -e "${RED}❌ Error: Unable to download from $url${NC}"
            return 1
        fi
    else
        # Local file - read directly
        if [ ! -f "$url" ]; then
            echo -e "${RED}❌ Error: Local file not found: $url${NC}"
            return 1
        fi
        raw_data=$(cat "$url")
    fi
    
    # Set CSV columns for this source
    if [ -n "$csv_columns" ]; then
        echo "   CSV Columns: $csv_columns"
        # Parse column specification
        IFS=',' read -ra CSV_COLUMNS <<< "$csv_columns"
        # Trim whitespace from columns
        for i in "${!CSV_COLUMNS[@]}"; do
            CSV_COLUMNS[$i]=$(echo "${CSV_COLUMNS[$i]}" | xargs)
        done
    else
        # Clear columns for default format
        CSV_COLUMNS=()
    fi
    
    # Parse based on format
    local parsed_data
    local pkg_count=0
    
    case "$format" in
        json)
            parsed_data="$raw_data"
            # Merge into global vulnerability data
            if [ -z "$VULN_DATA" ]; then
                VULN_DATA="$parsed_data"
            else
                VULN_DATA=$(json_merge "$VULN_DATA" "$parsed_data")
            fi
            pkg_count=$(json_object_length "$parsed_data")
            ;;
        csv)
            # FAST PATH: Parse CSV directly into lookup tables, bypass JSON
            # OPTIMIZED: Read count from first line, eval the rest (avoids grep)
            local eval_commands
            eval_commands=$(parse_csv_to_lookup_eval "$raw_data")

            # Extract package count from first line (format: CSV_PKG_COUNT=N)
            local first_line="${eval_commands%%$'\n'*}"
            pkg_count="${first_line#*=}"
            pkg_count=${pkg_count:-0}

            # Execute all assignments (including the count line, which is harmless)
            eval "$eval_commands"

            # NOTE: Do NOT set VULN_LOOKUP_BUILT=true here!
            # This allows build_vulnerability_lookup() to still process JSON data
            # that was loaded from other sources into VULN_DATA

            # For compatibility, also generate minimal JSON (just for display/merge if needed)
            # But we skip this since we already have the data in lookup tables
            VULN_DATA="${VULN_DATA:-{}}"
            ;;
        purl)
            # FAST PATH: Parse PURL directly into lookup tables, bypass JSON
            # OPTIMIZED: Read count from first line, eval the rest (avoids grep)
            local eval_commands
            eval_commands=$(parse_purl_to_lookup_eval "$raw_data")

            # Extract package count from first line (format: PURL_PKG_COUNT=N)
            local first_line="${eval_commands%%$'\n'*}"
            pkg_count="${first_line#*=}"
            pkg_count=${pkg_count:-0}

            # Execute all assignments (including the count line, which is harmless)
            eval "$eval_commands"

            # NOTE: Do NOT set VULN_LOOKUP_BUILT=true here!
            # This allows build_vulnerability_lookup() to still process JSON data
            # that was loaded from other sources into VULN_DATA

            # For compatibility, maintain minimal JSON structure
            VULN_DATA="${VULN_DATA:-{}}"
            ;;
        sarif)
            # FAST PATH: Parse SARIF format directly into lookup tables
            # OPTIMIZED: Read count from first line, eval the rest (avoids grep)
            local eval_commands
            eval_commands=$(parse_sarif_to_lookup_eval "$raw_data")

            # Extract package count from first line (format: SARIF_PKG_COUNT=N)
            local first_line="${eval_commands%%$'\n'*}"
            pkg_count="${first_line#*=}"
            pkg_count=${pkg_count:-0}

            # Execute all assignments (including the count line, which is harmless)
            eval "$eval_commands"

            # For compatibility, maintain minimal JSON structure
            VULN_DATA="${VULN_DATA:-{}}"
            ;;
        sbom|sbom-cyclonedx)
            # FAST PATH: Parse SBOM CycloneDX format directly into lookup tables
            # OPTIMIZED: Read count from first line, eval the rest (avoids grep)
            local eval_commands
            eval_commands=$(parse_sbom_to_lookup_eval "$raw_data")

            # Extract package count from first line (format: SBOM_PKG_COUNT=N)
            local first_line="${eval_commands%%$'\n'*}"
            pkg_count="${first_line#*=}"
            pkg_count=${pkg_count:-0}

            # Execute all assignments (including the count line, which is harmless)
            eval "$eval_commands"

            # For compatibility, maintain minimal JSON structure
            VULN_DATA="${VULN_DATA:-{}}"
            ;;
        trivy|trivy-json)
            # FAST PATH: Parse Trivy JSON format directly into lookup tables
            # OPTIMIZED: Read count from first line, eval the rest (avoids grep)
            local eval_commands
            eval_commands=$(parse_trivy_to_lookup_eval "$raw_data")

            # Extract package count from first line (format: TRIVY_PKG_COUNT=N)
            local first_line="${eval_commands%%$'\n'*}"
            pkg_count="${first_line#*=}"
            pkg_count=${pkg_count:-0}

            # Execute all assignments (including the count line, which is harmless)
            eval "$eval_commands"

            # For compatibility, maintain minimal JSON structure
            VULN_DATA="${VULN_DATA:-{}}"
            ;;
        *)
            echo -e "${RED}❌ Error: Unsupported format '$format'${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}✅ Loaded $pkg_count packages from $name${NC}"
    echo ""
    
    return 0
}

# Load configuration file
load_config_file() {
    local config_path="$1"
    
    if [ ! -f "$config_path" ]; then
        return 1
    fi
    
    echo -e "${BLUE}📋 Loading configuration from: $config_path${NC}"
    echo ""
    
    # Read config file content
    local config_content=$(cat "$config_path")
    
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
    fi
    
    # Parse config file and extract sources array
    local sources_array=$(json_get_array "$config_content" "sources")
    local sources_count=$(json_array_length "$sources_array")
    
    if [ "$sources_count" -eq 0 ]; then
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
                load_data_source "$url" "$format" "$name" "$columns"
            else
                load_data_source "$url" "" "$name" "$columns"
            fi
        done
    fi
    
    return 0
}

# Extract base version (without pre-release suffix like -rc, -alpha, -beta, etc.)
# For example: "19.0.0-rc-6230622a1a-20240610" -> "19.0.0"
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
    local v1="$1"
    local v2="$2"

    # Extract base versions for comparison (optimized with parameter expansion)
    local base1="${v1%%-*}"
    base1="${base1%%+*}"  # Strip build metadata (+build123)
    local base2="${v2%%-*}"
    base2="${base2%%+*}"

    # Split into major.minor.patch using parameter expansion (faster than cut/awk)
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)

    local major1="${parts1[0]:-0}"
    local minor1="${parts1[1]:-0}"
    local patch1="${parts1[2]:-0}"

    local major2="${parts2[0]:-0}"
    local minor2="${parts2[1]:-0}"
    local patch2="${parts2[2]:-0}"

    # Default to 0 if empty
    major1=${major1:-0}
    minor1=${minor1:-0}
    patch1=${patch1:-0}
    major2=${major2:-0}
    minor2=${minor2:-0}
    patch2=${patch2:-0}

    # Compare major
    if [ "$major1" -lt "$major2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$major1" -gt "$major2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Compare minor
    if [ "$minor1" -lt "$minor2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$minor1" -gt "$minor2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Compare patch
    if [ "$patch1" -lt "$patch2" ]; then
        COMPARE_RESULT="-1"
        return
    elif [ "$patch1" -gt "$patch2" ]; then
        COMPARE_RESULT="1"
        return
    fi

    # Base versions are equal, check pre-release
    # Pre-release versions have lower precedence than normal versions
    local has_prerelease1=false
    local has_prerelease2=false

    if [ "$v1" != "$base1" ]; then
        has_prerelease1=true
    fi
    if [ "$v2" != "$base2" ]; then
        has_prerelease2=true
    fi

    # If one has pre-release and other doesn't
    if [ "$has_prerelease1" = true ] && [ "$has_prerelease2" = false ]; then
        COMPARE_RESULT="-1"  # pre-release < release
        return
    elif [ "$has_prerelease1" = false ] && [ "$has_prerelease2" = true ]; then
        COMPARE_RESULT="1"   # release > pre-release
        return
    fi

    # Both have pre-release: compare pre-release identifiers lexicographically
    # Handles common patterns: alpha < beta < rc, canary.1 < canary.2
    if [ "$has_prerelease1" = true ] && [ "$has_prerelease2" = true ]; then
        local pre1="${v1#*-}"
        local pre2="${v2#*-}"
        # Strip build metadata from pre-release part
        pre1="${pre1%%+*}"
        pre2="${pre2%%+*}"
        if [[ "$pre1" < "$pre2" ]]; then
            COMPARE_RESULT="-1"
            return
        elif [[ "$pre1" > "$pre2" ]]; then
            COMPARE_RESULT="1"
            return
        fi
    fi

    COMPARE_RESULT="0"
}

# Convert semver ranges (~ and ^) to standard range format
# ~1.2.3 -> >=1.2.3 <1.3.0
# ^1.2.3 -> >=1.2.3 <2.0.0
expand_semver_range() {
    local range="$1"

    # Handle tilde ranges: ~1.2.3 means >=1.2.3 <1.3.0
    if [[ "$range" =~ ^~([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"
        local prerelease="${BASH_REMATCH[4]}"
        local next_minor=$((minor + 1))
        echo ">=$major.$minor.$patch$prerelease <$major.$next_minor.0"
        return 0
    fi

    # Handle caret ranges: ^1.2.3 means >=1.2.3 <2.0.0
    if [[ "$range" =~ ^\^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"
        local prerelease="${BASH_REMATCH[4]}"

        # For ^0.x.y, it's more restrictive
        if [ "$major" = "0" ]; then
            if [ "$minor" = "0" ]; then
                # ^0.0.x -> >=0.0.x <0.0.(x+1)
                local next_patch=$((patch + 1))
                echo ">=$major.$minor.$patch$prerelease <$major.$minor.$next_patch"
            else
                # ^0.x.y -> >=0.x.y <0.(x+1).0
                local next_minor=$((minor + 1))
                echo ">=$major.$minor.$patch$prerelease <$major.$next_minor.0"
            fi
        else
            # ^x.y.z -> >=x.y.z <(x+1).0.0
            local next_major=$((major + 1))
            echo ">=$major.$minor.$patch$prerelease <$next_major.0.0"
        fi
        return 0
    fi

    # Return original if no semver range detected
    echo "$range"
}

# Check if a version is within a range
# Range format: ">1.0.0 <=2.0.0" or ">=1.0.0 <2.0.0" etc.
# Pre-release versions are included if their base version is within the range
version_in_range() {
    local version="$1"
    local range="$2"

    # Expand semver ranges first
    range=$(expand_semver_range "$range")

    # Guard against empty range (should not match any version)
    if [ -z "$range" ]; then
        return 1
    fi

    # Get base version for pre-release handling
    local base_version=$(get_base_version "$version")
    local is_prerelease=false
    if [ "$version" != "$base_version" ]; then
        is_prerelease=true
    fi
    
    # Parse the range - split by space
    local conditions=($range)
    
    for condition in "${conditions[@]}"; do
        local operator=""
        local range_version=""
        
        # Extract operator and version
        if [[ "$condition" =~ ^(\>=|\<=|\>|\<)(.+)$ ]]; then
            operator="${BASH_REMATCH[1]}"
            range_version="${BASH_REMATCH[2]}"
        else
            # No operator, skip invalid condition
            continue
        fi
        
        # For pre-release versions, use base version for comparison
        # This allows 19.0.0-rc.1 to be considered as within >=19.0.0
        # OPTIMIZED: dispatch on CHECK_ECO and use COMPARE_RESULT (avoids subshell).
        # npm/everything-else routes to the unchanged compare_versions; only
        # ecosystems with their own comparator (e.g. golang) diverge.
        if [ "$is_prerelease" = true ]; then
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
    
    return 0  # All conditions passed
}

# Check if a version matches a vulnerable version (exact or pre-release of it)
version_matches_vulnerable() {
    local installed_version="$1"
    local versions="$2"
    
    # Exact match
    if [ "$installed_version" = "$versions" ]; then
        return 0
    fi
    
    # Check if installed version is a pre-release of the vulnerable version
    # For example: "19.0.0-rc-xxx" should match "19.0.0"
    local installed_base=$(get_base_version "$installed_version")
    
    if [ "$installed_base" = "$versions" ] && [ "$installed_version" != "$installed_base" ]; then
        # It's a pre-release version (has suffix) and base matches
        return 0
    fi
    
    return 1
}

# Build vulnerability lookup tables from VULN_DATA for O(1) lookups
# This parses the JSON once and stores in associative arrays
# OPTIMIZED: awk generates bash eval statements directly, avoiding slow bash loops
# NOTE: This function MERGES JSON data with existing lookup tables (e.g., from CSV)
# Comparator dispatch — routes a candidate/range version comparison to the
# ecosystem-appropriate comparator. Matching code passes CHECK_ECO (set by
# check_vulnerability); everything that is not a special-cased ecosystem falls
# through to the unchanged npm-semver compare_versions (behavior freeze).
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
# Go module version comparator (semver-2 semantics, matching golang.org/x/mod
# semver ordering). Routed to from compare_versions_eco when CHECK_ECO=golang.
#
# Differences from the npm compare_versions this must NOT be folded into:
#   - a leading `v` is part of every Go module version and is stripped;
#   - `+incompatible` (and any `+build` metadata) is dropped, not treated as a
#     pre-release marker (npm's compare_versions would mis-rank 2.0.0+incompatible);
#   - pre-release identifiers follow the full semver-2 rules: dot-split, numeric
#     identifiers compare numerically and rank below alphanumeric ones, and a
#     longer identifier list wins when it is a prefix-superset of a shorter one.
# Go pseudo-versions (v0.0.0-20191109021931-daa7c04131f5) fall out of these
# rules for free: the timestamp+hash after the dash is a single alphanumeric
# pre-release identifier whose fixed-width timestamp prefix sorts chronologically
# under a plain lexical comparison.
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell in the hot path.
compare_versions_go() {
    # Strip the leading module `v` and any build metadata (+incompatible/+meta).
    local v1="${1#v}"
    local v2="${2#v}"
    v1="${v1%%+*}"
    v2="${v2%%+*}"

    # Split base (x.y.z) from the pre-release tail (first '-' onward).
    local base1="${v1%%-*}"
    local base2="${v2%%-*}"

    # --- Compare base x.y.z numerically ---
    local IFS='.'
    local parts1=($base1)
    local parts2=($base2)
    unset IFS
    local i n1 n2
    for i in 0 1 2; do
        n1="${parts1[$i]:-0}"
        n2="${parts2[$i]:-0}"
        if [ "$n1" -lt "$n2" ]; then COMPARE_RESULT="-1"; return; fi
        if [ "$n1" -gt "$n2" ]; then COMPARE_RESULT="1"; return; fi
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

compare_versions_gem() {
    # Canonicalize: '-' introduces a prerelease, identically to '.pre.'.
    local v1="${1//-/.pre.}"
    local v2="${2//-/.pre.}"

    _gem_tokenize "$v1"
    local -a segs1=("${_GEM_SEGS[@]}")
    _gem_tokenize "$v2"
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
# WRAPPER around the frozen 3-part npm compare_versions (never modified, per
# the golang/pep440/gem/maven comparators' pattern) rather than a call into
# it, because compare_versions only knows Major.Minor.Patch — it has no
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
#     dot-split loop as compare_versions_go's pre-release tail (reused here
#     verbatim, adapted to the case-insensitive rule below), NOT
#     compare_versions' whole-pre-release-string lexical compare (which would
#     mis-rank "beta.10" below "beta.9");
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
build_vulnerability_lookup() {
    if [ "$VULN_LOOKUP_BUILT" = true ]; then
        return 0
    fi

    # NOTE: Do NOT clear existing data - we want to merge with CSV data if present
    # VULN_EXACT_LOOKUP=()
    # VULN_RANGE_LOOKUP=()
    
    # Use awk to parse JSON and generate bash eval statements directly
    # This avoids the slow while-read loop in bash
    local eval_commands
    eval_commands=$(echo "$VULN_DATA" | awk '
    BEGIN {
        pkg = ""
        in_ver = 0
        in_range = 0
    }
    
    # Function to escape single quotes for bash
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
        return s
    }
    
    {
        # Work character by character to handle JSON properly
        line = $0
        n = length(line)
        
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            
            # Simple state machine
            if (c == "\"") {
                # Start of quoted string - find the end
                start = i + 1
                i++
                while (i <= n) {
                    c2 = substr(line, i, 1)
                    if (c2 == "\\") {
                        i++  # Skip escaped char
                    } else if (c2 == "\"") {
                        break
                    }
                    i++
                }
                end = i - 1
                str = substr(line, start, end - start + 1)
                
                # Check what comes after the string
                rest = substr(line, i + 1)
                if (match(rest, /^[[:space:]]*:[[:space:]]*\{/)) {
                    # This is a package name
                    pkg = str
                    in_ver = 0
                    in_range = 0
                } else if (str == "versions" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
                    in_ver = 1
                    in_range = 0
                } else if (str == "versions_range" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
                    in_range = 1
                    in_ver = 0
                } else if (in_ver && pkg != "" && str != "") {
                    # Aggregate exact versions by package
                    if (pkg in exact_vers) {
                        exact_vers[pkg] = exact_vers[pkg] "|" str
                    } else {
                        exact_vers[pkg] = str
                    }
                } else if (in_range && pkg != "" && str != "") {
                    # Aggregate ranges by package
                    if (pkg in range_vers) {
                        range_vers[pkg] = range_vers[pkg] "|" str
                    } else {
                        range_vers[pkg] = str
                    }
                }
            } else if (c == "]") {
                in_ver = 0
                in_range = 0
            }
        }
    }
    END {
        # JSON sources carry no ecosystem info -> wildcard namespace "*:"
        # Output bash eval statements that MERGE with existing data
        for (pkg in exact_vers) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(exact_vers[pkg]), escape_sq(nk), escape_sq(exact_vers[pkg])
        }
        for (pkg in range_vers) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(range_vers[pkg]), escape_sq(nk), escape_sq(range_vers[pkg])
        }
    }
    ')

    # Execute all assignments at once (much faster than while-read loop)
    eval "$eval_commands"
    
    VULN_LOOKUP_BUILT=true
}

# Function to check if a package+version is vulnerable
# Uses pre-built lookup tables for O(1) access
# Reports ALL matching advisories (not just the first)
#
# Args: eco name version source_file
# Probes BOTH the ecosystem namespace (eco:name) and the wildcard namespace
# (*:name) so that ecosystem-tagged feeds and ecosystem-agnostic feeds
# (CSV/JSON/SARIF) both match, without cross-ecosystem collisions.
check_vulnerability() {
    local eco="$1"
    local name="$2"
    local version="$3"
    local source="$4"

    # Forward wiring: later tasks dispatch version comparators on the ecosystem.
    CHECK_ECO="$eco"

    # Candidate lookup keys: ecosystem namespace first, then wildcard.
    local -a probe_keys=("${eco}:${name}")
    if [ "$eco" != "*" ]; then
        probe_keys+=("*:${name}")
    fi

    # Fast existence check across all probes (O(1) each)
    local any_exists=false
    local pk
    for pk in "${probe_keys[@]}"; do
        if [ -n "${VULN_EXACT_LOOKUP[$pk]+x}" ] || [ -n "${VULN_RANGE_LOOKUP[$pk]+x}" ]; then
            any_exists=true
            break
        fi
    done
    [ "$any_exists" = false ] && return 1

    # Advisories are grouped/looked up under the SCANNED package's namespace.
    local exact_meta_key="${eco}:${name}@${version}"
    local found=false
    local first_match_msg=""

    # Skip metadata collection if already done for this package@version (called from another file)
    local already_checked=false
    if [ -n "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
        already_checked=true
    fi

    # Track seen GHSA IDs for deduplication across BOTH namespaces
    declare -A _seen_ghsas

    for pk in "${probe_keys[@]}"; do
        # Get vulnerable versions/ranges stored under this namespaced key
        local vulnerability_versions="${VULN_EXACT_LOOKUP[$pk]:-}"
        local vulnerability_ranges="${VULN_RANGE_LOOKUP[$pk]:-}"

        # Check exact version matches
        if [ -n "$vulnerability_versions" ]; then
            IFS='|' read -ra vers_array <<< "$vulnerability_versions"
            for vulnerability_ver in "${vers_array[@]}"; do
                [ -z "$vulnerability_ver" ] && continue
                if version_matches_vulnerable "$version" "$vulnerability_ver"; then
                    if [ "$found" = false ]; then
                        if [ "$version" = "$vulnerability_ver" ]; then
                            first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable)${NC}"
                        else
                            first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable - pre-release of $vulnerability_ver)${NC}"
                        fi
                    fi
                    if [ "$already_checked" = false ]; then
                        local ver_meta_key="${pk}@${vulnerability_ver}"
                        local sev="${VULN_METADATA_SEVERITY[$ver_meta_key]:-}"
                        local ghsa="${VULN_METADATA_GHSA[$ver_meta_key]:-}"
                        local cve="${VULN_METADATA_CVE[$ver_meta_key]:-}"
                        local msrc="${VULN_METADATA_SOURCE[$ver_meta_key]:-}"
                        local fix="${VULN_METADATA_FIX[$ver_meta_key]:-}"
                        # Cross-namespace dedup: skip if this advisory (GHSA) already recorded
                        if [ -n "$ghsa" ] && [ -n "${_seen_ghsas[$ghsa]+x}" ]; then
                            found=true
                            continue
                        fi
                        [ -n "$ghsa" ] && _seen_ghsas[$ghsa]=1
                        local advisory_entry="${sev};${ghsa};${cve};${msrc};${fix}"
                        if [ -z "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
                            VULN_ADVISORIES[$exact_meta_key]="$advisory_entry"
                        else
                            VULN_ADVISORIES[$exact_meta_key]+="||${advisory_entry}"
                        fi
                        # Set VULN_METADATA_* for first match (backward compat with exports)
                        if [ -z "${VULN_METADATA_SEVERITY[$exact_meta_key]+x}" ]; then
                            [ -n "$sev" ] && VULN_METADATA_SEVERITY[$exact_meta_key]="$sev"
                            [ -n "$ghsa" ] && VULN_METADATA_GHSA[$exact_meta_key]="$ghsa"
                            [ -n "$cve" ] && VULN_METADATA_CVE[$exact_meta_key]="$cve"
                            [ -n "$msrc" ] && VULN_METADATA_SOURCE[$exact_meta_key]="$msrc"
                        fi
                    fi
                    found=true
                fi
            done
        fi

        # Check version ranges - check ALL ranges to report all matching advisories
        # Deduplicate by GHSA ID and skip matches where version is already patched
        if [ -n "$vulnerability_ranges" ]; then
            IFS='|' read -ra ranges_array <<< "$vulnerability_ranges"
            for range in "${ranges_array[@]}"; do
                [ -z "$range" ] && continue
                if version_in_range "$version" "$range"; then
                    local range_meta_key="${pk}:${range}"
                    local ghsa="${VULN_METADATA_GHSA[$range_meta_key]:-}"

                    # Skip if version is patched for this GHSA (version >= highest upper bound)
                    if [ -n "$ghsa" ]; then
                        local patched_key="${pk}:${ghsa}"
                        if [ -n "${VULN_PATCHED[$patched_key]+x}" ]; then
                            local patched_ver="${VULN_PATCHED[$patched_key]}"
                            # Dispatch on the scanned ecosystem so patched-version
                            # bookkeeping orders correctly per ecosystem (e.g. a
                            # pypi 1.0.post1 bound mis-orders under npm-semver).
                            compare_versions_eco "${CHECK_ECO:-npm}" "$version" "$patched_ver"
                            if [ "$COMPARE_RESULT" != "-1" ]; then
                                # Version >= patched version, not vulnerable for this GHSA
                                continue
                            fi
                        fi
                    fi

                    # Deduplicate by GHSA ID (across both namespaces)
                    if [ -n "$ghsa" ]; then
                        if [ -n "${_seen_ghsas[$ghsa]+x}" ]; then
                            continue
                        fi
                        _seen_ghsas[$ghsa]=1
                    fi

                    if [ "$found" = false ]; then
                        first_match_msg="${RED}⚠️  [$source] $name@$version (vulnerable - matches range: $range)${NC}"
                    fi
                    if [ "$already_checked" = false ]; then
                        local sev="${VULN_METADATA_SEVERITY[$range_meta_key]:-}"
                        local cve="${VULN_METADATA_CVE[$range_meta_key]:-}"
                        local msrc="${VULN_METADATA_SOURCE[$range_meta_key]:-}"
                        local fix="${VULN_METADATA_FIX[$range_meta_key]:-}"
                        local advisory_entry="${sev};${ghsa};${cve};${msrc};${fix}"
                        if [ -z "${VULN_ADVISORIES[$exact_meta_key]+x}" ]; then
                            VULN_ADVISORIES[$exact_meta_key]="$advisory_entry"
                        else
                            VULN_ADVISORIES[$exact_meta_key]+="||${advisory_entry}"
                        fi
                        # Set VULN_METADATA_* for first match (backward compat with exports)
                        if [ -z "${VULN_METADATA_SEVERITY[$exact_meta_key]+x}" ]; then
                            [ -n "$sev" ] && VULN_METADATA_SEVERITY[$exact_meta_key]="$sev"
                            [ -n "$ghsa" ] && VULN_METADATA_GHSA[$exact_meta_key]="$ghsa"
                            [ -n "$cve" ] && VULN_METADATA_CVE[$exact_meta_key]="$cve"
                            [ -n "$msrc" ] && VULN_METADATA_SOURCE[$exact_meta_key]="$msrc"
                        fi
                    fi
                    found=true
                fi
            done
        fi
    done
    unset _seen_ghsas

    if [ "$found" = true ]; then
        echo -e "$first_match_msg"
        FOUND_VULNERABLE=1
        VULNERABLE_PACKAGES+=("$source|$eco|$name@$version")
        return 0
    fi

    # Package is in the list but installed version is not vulnerable
    # Silently return to avoid spamming output for large vulnerability databases
    return 1
}

# Function to analyze a package-lock.json file
# Optimized: uses awk for batch extraction instead of JSON parsing loops
# Uses POSIX-compatible awk syntax for macOS compatibility
analyze_package_lock() {
    local lockfile="$1"
    local eco="${2:-npm}"

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
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
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
# ecosystems selected by a directory PATH pattern instead of a fixed lockfile
# basename. GitHub Actions is the only one: workflow YAML lives at a well-known
# path (.github/workflows/*.yml|*.yaml) under ARBITRARY filenames, so `find
# -name` cannot select it and `basename` cannot dispatch it. Both the find-args
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
# This depth-tracking approach assumes composer's own pretty-printed output
# (json_encode(..., JSON_PRETTY_PRINT): one token per line, exactly what
# `composer install`/`composer require` always produce), the same line-
# oriented assumption every other parser in this codebase makes.
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
    packages=$(awk '
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

# Parse a pom.xml. A line-oriented awk state machine walks each <dependency> block
# and captures its <groupId>, <artifactId> and <version> child text (tolerating a
# same-line "<groupId>x</groupId>" form). A dependency is REPORTED only when it has
# a literal, resolvable version: entries whose version is absent or contains "${"
# (an unresolved property such as ${spring.version}) are SKIPPED — this parser does
# NOT resolve properties or parent/dependencyManagement inheritance, a documented
# manifest-grade limitation (the same class of limitation every non-lockfile parser
# in this codebase carries). <dependency> blocks anywhere are accepted (project
# <dependencies> and <dependencyManagement> alike). Nested <exclusions> carry their
# own <groupId>/<artifactId> children, so that region is skipped to avoid clobbering
# the enclosing dependency's coordinates. The opening tag is matched as
# "<dependency" followed by a space or '>' so that "<dependencies>" (the wrapper)
# never triggers a block.
analyze_pom_xml() {
    local lockfile="$1"
    local eco="${2:-maven}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    # Return the inner text of <tag>...</tag> on this line, or the sentinel
    # "\001" (never a valid coordinate) when the tag is not present/closed here.
    function inner(line, tag,   open, s, rest, e, val) {
        open = "<" tag ">"
        s = index(line, open)
        if (s == 0) return "\001"
        rest = substr(line, s + length(open))
        e = index(rest, "</" tag ">")
        if (e == 0) return "\001"
        val = substr(rest, 1, e - 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        return val
    }
    BEGIN { in_dep = 0; in_excl = 0 }
    {
        line = $0
        gsub(/\r/, "", line)

        # Open/capture/close are handled within the SAME line pass (not via
        # "next"), so a whole "<dependency>...</dependency>" on one line, or an
        # opening tag sharing a line with its first child, is still captured.
        if (line ~ /<dependency[[:space:]>]/) {
            in_dep = 1; in_excl = 0
            g = ""; a = ""; v = ""; have_v = 0
        }
        if (in_dep) {
            if (line ~ /<exclusions>/) in_excl = 1
            # Skip coordinate capture inside a nested <exclusions> block (its
            # <groupId>/<artifactId> children would otherwise clobber the dep).
            if (!in_excl) {
                val = inner(line, "groupId");    if (val != "\001") g = val
                val = inner(line, "artifactId"); if (val != "\001") a = val
                val = inner(line, "version");    if (val != "\001") { v = val; have_v = 1 }
            }
            if (line ~ /<\/exclusions>/) in_excl = 0
        }
        if (line ~ /<\/dependency>/) {
            if (in_dep && g != "" && a != "" && have_v && v != "" && index(v, "${") == 0) {
                print g ":" a "|" v
            }
            in_dep = 0; in_excl = 0
        }
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
# "type" ("Direct" | "Transitive" | "Project") and, for Direct/Transitive, a
# "resolved" version. This is one nesting level deeper than composer.lock's
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
# type is Direct or Transitive AND a resolved version was captured.
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
    packages=$(awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "" && (pkg_type == "Direct" || pkg_type == "Transitive")) {
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
# EXTRACTION: the quoted map key (the dependency's app name — what every real
# mix.lock uses, and what hex.pm PURLs/advisories key on too) is the FIRST
# quoted string on the line. The version is the FIRST quoted string AFTER the
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

        # Package name: the first quoted string on the line (the map key).
        if (!match(line, /"[^"]+"/)) next
        name = substr(line, RSTART + 1, RLENGTH - 2)

        # Walk past "{:hex," then past the ":atom_name," element to reach
        # the tuple'\''s 3rd element, whose FIRST quoted string is the version.
        hexpos = index(line, "{:hex,")
        if (hexpos == 0) next
        rest = substr(line, hexpos + 6)
        commapos = index(rest, ",")
        if (commapos == 0) next
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
# "http://" or "https://" scheme, strip a trailing ".git", lowercase the
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
    packages=$(awk '
    function emit_pkg() {
        if (url != "" && ver != "") {
            canon = url
            sub(/^https?:\/\//, "", canon)
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
    ' "$lockfile" 2>/dev/null | sort -u)

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
export_vulnerabilities_json() {
    local output_file="${1:-vulnerabilities.json}"

    {
        echo "{"
        echo '  "vulnerabilities": ['

        local first=true
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file eco pkg <<< "$vuln"

            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi

            echo -n '    {'
            echo -n '"package": "'"$pkg"'", '
            echo -n '"file": "'"$file"'"'
            echo -n ', "ecosystem": "'"$eco"'"'

            # Add metadata if available (namespaced key; fall back to name-only, scoped-safe)
            local meta_key="${eco}:${pkg}"
            local pkg_name_only="${pkg%@*}"
            local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
            local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
            local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
            local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

            if [ -n "$severity" ]; then
                echo -n ', "severity": "'"$severity"'"'
            fi

            if [ -n "$ghsa" ]; then
                echo -n ', "ghsa": "'"$ghsa"'"'
            fi

            if [ -n "$cve" ]; then
                echo -n ', "cve": "'"$cve"'"'
            fi

            if [ -n "$source" ]; then
                echo -n ', "source": "'"$source"'"'
            fi

            echo -n '}'
        done

        echo ""
        echo '  ],'
        echo '  "summary": {'
        local unique_vulns=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | awk -F'|' '{print $2":"$3}' | sort -u | wc -l | tr -d ' ')
        local total_occurrences=${#VULNERABLE_PACKAGES[@]}
        echo '    "total_unique_vulnerabilities": '"$unique_vulns"','
        echo '    "total_occurrences": '"$total_occurrences"
        echo '  }'
        echo "}"
    } > "$output_file"

    echo -e "${GREEN}✓ JSON report exported to: $output_file${NC}"
}

# Export vulnerabilities to CSV format
# Columns: package, file, severity, ghsa, cve, source, ecosystem
export_vulnerabilities_csv() {
    local output_file="${1:-vulnerabilities.csv}"

    # Write CSV header
    echo "package,file,severity,ghsa,cve,source,ecosystem" > "$output_file"

    # Write vulnerability data
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file eco pkg <<< "$vuln"

        # Check both namespaced and name-only (scoped-safe) for metadata
        local meta_key="${eco}:${pkg}"
        local pkg_name_only="${pkg%@*}"
        local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
        local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
        local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
        local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"

        # Escape fields that might contain commas
        pkg=$(echo "$pkg" | sed 's/"/""/g')
        file=$(echo "$file" | sed 's/"/""/g')

        echo "\"$pkg\",\"$file\",\"$severity\",\"$ghsa\",\"$cve\",\"$source\",\"$eco\"" >> "$output_file"
    done

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
#   composer/nuget/githubactions -> lowercase
#   swift          -> strip http(s):// scheme and trailing .git, lowercase
#   npm/golang/cargo/gem/pub/hex -> name as-is
# $source is "ghsa" or "osv" and controls the GHSA-id extraction + source= param.
FEED_JQ_PROGRAM='
def emit_name($type; $name):
    if $type == "pypi" then ($name | ascii_downcase | gsub("[-_.]+"; "-"))
    elif $type == "maven" then ($name | gsub(":"; "/"))
    elif ($type == "composer" or $type == "nuget" or $type == "githubactions") then ($name | ascii_downcase)
    elif $type == "swift" then ($name | sub("^https?://"; "") | sub("\\.git$"; "") | ascii_downcase)
    else $name end;

.id as $id |
(.database_specific.severity //
 (.severity[]? | select(.type == "CVSS_V3" or .type == "CVSS_V2") | .score |
  if . then
    (. | capture("CVSS:[^/]+/[^/]+/(?<score>[0-9.]+)") | .score | tonumber |
     if . >= 9.0 then "CRITICAL"
     elif . >= 7.0 then "HIGH"
     elif . >= 4.0 then "MODERATE"
     else "LOW" end)
  else null end) //
 "UNKNOWN") as $severity |

(.aliases // []) as $aliases |
(if $source == "ghsa" then
    (if ($id | startswith("GHSA-")) then $id else "" end)
 else
    ($aliases | map(select(startswith("GHSA-"))) | .[0] // "")
 end) as $ghsa |
($aliases | map(select(startswith("CVE-"))) | .[0] // "") as $cve |

.affected[]? |
.package.ecosystem as $e |
($ecomap[$e] // "") as $type |
select($type != "") |
(emit_name($type; .package.name)) as $pkg |
(
    (.ranges[]? |
        select(.type == "SEMVER" or .type == "ECOSYSTEM") |
        .events |
        map(select(.introduced or .fixed or .last_affected)) |
        if length > 0 then
            reduce .[] as $event (
                {introduced: null, fixed: null, last_affected: null};
                if $event.introduced then
                    .introduced = $event.introduced
                elif $event.fixed then
                    .fixed = $event.fixed
                elif $event.last_affected then
                    .last_affected = $event.last_affected
                else . end
            ) |
            ([
                ("severity=" + ($severity | ascii_downcase)),
                (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                (if $cve != "" then "cve=" + $cve else empty end),
                ("source=" + $source)
            ] | join("&")) as $params |

            if .introduced and .fixed then
                "pkg:\($type)/\($pkg)@>=\(.introduced) <\(.fixed)?\($params)"
            elif .introduced and .last_affected then
                "pkg:\($type)/\($pkg)@>=\(.introduced) <=\(.last_affected)?\($params)"
            elif .introduced then
                "pkg:\($type)/\($pkg)@>=\(.introduced)?\($params)"
            elif .fixed then
                "pkg:\($type)/\($pkg)@<\(.fixed)?\($params)"
            elif .last_affected then
                "pkg:\($type)/\($pkg)@<=\(.last_affected)?\($params)"
            else empty end
        else empty end
    ),
    # Output exact versions for entries without SEMVER/ECOSYSTEM ranges (e.g., MAL advisories)
    (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
        ([
            ("severity=" + ($severity | ascii_downcase)),
            (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
            (if $cve != "" then "cve=" + $cve else empty end),
            ("source=" + $source)
        ] | join("&")) as $params |
        .versions[]? |
        "pkg:\($type)/\($pkg)@\(.)?\($params)"
    else empty end)
)
'

# Run FEED_JQ_PROGRAM over every *.json file under an input directory, in
# parallel, and append the raw (unsorted) PURL lines to a combined file.
#   $1 input dir   $2 source ("ghsa"|"osv")   $3 ecomap JSON   $4 combined out
#
# Robustness: 8 parallel workers each write to their OWN temp file — never a
# shared pipe — because concurrent jq processes writing to one pipe interleave
# non-atomically and tear PURL lines (observed frequently under load). Each
# worker runs jq once per file (error isolation for the rare malformed
# advisory), so a single bad JSON never drops its whole chunk. This keeps the
# "xargs -P 8 parallel jq" design while producing deterministic, uncorrupted
# feeds. Callers sort/split the combined file (LC_ALL=C for locale stability).
feed_emit_raw() {
    local in_dir="$1" src="$2" ecomap="$3" combined="$4"
    local parts_dir
    parts_dir=$(mktemp -d)
    export FEED_JQ_PROGRAM
    find "$in_dir" -name "*.json" -type f -print0 | \
        FEED_SRC="$src" FEED_ECOMAP="$ecomap" PARTS_DIR="$parts_dir" \
        xargs -0 -P 8 -n 400 sh -c '
            out=$(mktemp "$PARTS_DIR/part.XXXXXX") || exit 1
            for f in "$@"; do
                jq -r --arg source "$FEED_SRC" --argjson ecomap "$FEED_ECOMAP" "$FEED_JQ_PROGRAM" "$f" 2>/dev/null
            done > "$out"
        ' _ 2>/dev/null || true
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
    git clone --filter=blob:none --no-checkout --depth 1 "$GHSA_REPO" "$CLONE_DIR" 2>&1 | grep -v "^remote:" | grep -v "^Cloning" | grep -v "^$" || true
    (
        cd "$CLONE_DIR" || exit 1
        git sparse-checkout init --cone 2>&1 | grep -v "^$" || true
        git sparse-checkout set advisories/github-reviewed 2>&1 | grep -v "^$" || true
        git checkout 2>&1 | grep -v "^remote:" | grep -v "^Your branch" | grep -v "^$" || true
    ) || true

    echo "Processing GHSA advisories for: ${valid_types[*]}" >&2

    local file_count
    file_count=$(find "$CLONE_DIR/advisories/github-reviewed" -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count advisory files" >&2
    echo "Using parallel processing (single pass, all ecosystems)..." >&2

    # SINGLE parallel jq pass emitting PURLs for every requested ecosystem.
    local combined="$ghsa_tmp/combined.purl"
    feed_emit_raw "$CLONE_DIR/advisories/github-reviewed" "ghsa" "$ecomap" "$combined"

    # Split combined output by pkg:<type>/ prefix into per-ecosystem files.
    local base out_file line_count
    for t in "${valid_types[@]}"; do
        base=$(default_feed_filename "ghsa" "$t")
        out_file="$out_dir/$base"
        # LC_ALL=C: deterministic byte-order sort, reproducible across locales
        # (matches the CI runner and keeps committed feed diffs to real churn).
        { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u > "$out_file"
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
        if ! curl -sL "https://osv-vulnerabilities.storage.googleapis.com/${osv_dir}/all.zip" -o "$zip_file"; then
            echo "⚠️  Failed to download OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            continue
        fi

        echo "Extracting $eco_string vulnerabilities..." >&2
        if ! unzip -q "$zip_file" -d "$eco_tmp" 2>/dev/null; then
            echo "⚠️  Failed to extract OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            continue
        fi

        file_count=$(find "$eco_tmp" -name "*.json" -type f | wc -l | tr -d ' ')
        echo "Processing $file_count $eco_string files (parallel)..." >&2

        # Robust parallel emission, then deterministic C-locale sort/dedupe.
        local combined="$eco_tmp/combined.purl"
        feed_emit_raw "$eco_tmp" "osv" "$ecomap" "$combined"
        LC_ALL=C sort -u "$combined" > "$out_file" || true

        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2

        rm -rf "$eco_tmp"
    done

    echo "OSV processing complete" >&2
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

    # Generate OSV feeds (one zip per ecosystem)
    echo "Generating OSV feeds for all ecosystems..."
    fetch_osv
    echo ""

    # Generate GHSA feeds (single clone, single pass, split per ecosystem)
    echo "Generating GHSA feeds for all ecosystems..."
    fetch_ghsa
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
}

# Find default source file with fallback logic
# Tries multiple locations in order:
# 1. Homebrew installation path
# 2. Local ./data/ directory
# 3. Docker /app/data/ directory
# 4. Remote GitHub URL
# Returns path/URL if found, empty string if not found
find_default_source() {
    local source_file="$1"  # e.g., "ghsa.purl" or "osv.purl"

    # Try Homebrew path
    if command -v brew &> /dev/null; then
        local brew_path="$(brew --prefix)/share/package-checker/data/$source_file"
        if [ -f "$brew_path" ]; then
            echo "$brew_path"
            return 0
        fi
    fi

    # Try local ./data/ directory
    if [ -f "./data/$source_file" ]; then
        echo "./data/$source_file"
        return 0
    fi

    # Try Docker /app/data/ directory
    if [ -f "/app/data/$source_file" ]; then
        echo "/app/data/$source_file"
        return 0
    fi

    # Try remote GitHub URL as last resort
    local github_url="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/$source_file"
    if curl --output /dev/null --silent --head --fail "$github_url" 2>/dev/null; then
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
#              nuget, pub, hex, swift, githubactions)
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
        gem)           echo "bundle audit" ;;
        composer)      echo "composer audit" ;;
        maven)         echo "# re-run your SCA scan (e.g. OWASP dependency-check, Trivy)" ;;
        nuget)         echo "dotnet list package --vulnerable" ;;
        pub)           echo "dart pub outdated" ;;
        hex)           echo "mix hex.audit" ;;
        swift)         echo "# re-resolve and re-scan Package.resolved" ;;
        githubactions) echo "# re-run package-checker (or pin to the patched commit SHA)" ;;
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
            npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions) continue ;;
        esac
        echo -e "${RED}❌ Error: Unknown ecosystem '$token' in --ecosystems${NC}"
        echo "Valid values: aliases (${KNOWN_LOCKFILE_ALIASES// /, }) or purl types (npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions)"
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

# Discover lockfiles and package.json files under the scan directory, populate
# the LOCKFILES / PACKAGE_JSON_FILES globals, and record which ecosystems are
# present in DETECTED_ECOSYSTEMS. Runs BEFORE feed loading so detection can
# drive which default feeds are pulled. Reads main()'s locals (target_path,
# lockfile_types, only_package_json, only_lockfiles, use_github) via bash
# dynamic scope; sets SEARCH_DIR/LOCKFILES/PACKAGE_JSON_FILES as globals.
discover_project_files() {
    # Determine the (global) search directory
    SEARCH_DIR="${target_path:-.}"
    if [ "$use_github" = true ] && [ -d "$GITHUB_OUTPUT_DIR" ]; then
        SEARCH_DIR="$GITHUB_OUTPUT_DIR"
    elif [ -n "$target_path" ]; then
        if [ ! -d "$SEARCH_DIR" ]; then
            echo -e "${RED}❌ Error: Target path does not exist: $target_path${NC}"
            exit 1
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
                    exit 1 ;;
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

    # ---- Find lockfiles ----
    local TEMP_LOCKFILES=""
    if [ "$only_package_json" = false ] && [ ${#selected_basenames[@]} -gt 0 ]; then
        local find_args=( "$SEARCH_DIR" '(' )
        local i=0
        for bn in "${selected_basenames[@]}"; do
            [ "$i" -gt 0 ] && find_args+=( -o )
            find_args+=( -name "$bn" )
            i=$((i + 1))
        done
        find_args+=( ')' -type f )
        local ignore_path
        for ignore_path in "${CONFIG_IGNORE_PATHS[@]}"; do
            find_args+=( ! -path "*/$ignore_path/*" )
        done
        TEMP_LOCKFILES=$(find "${find_args[@]}")
    fi

    # ---- Find PATH-discovered ecosystem files (e.g. GitHub Actions workflows)
    # Selected by a directory PATH pattern rather than a lockfile basename, so
    # each entry expands its stored path-glob + name-globs into a dedicated find
    # predicate. Results are merged into TEMP_LOCKFILES so they flow through the
    # SAME git-ignore filter and the SAME analysis loop as basename lockfiles
    # (letting workflow findings coexist with npm/etc. in one scan). The `.git`
    # ignore entry expands to `! -path "*/.git/*"`, which does NOT match
    # ".../.github/workflows/..." (there is no "/.git/" segment there), so
    # workflow discovery is never swallowed by the .git exclude.
    if [ "$only_package_json" = false ] && [ ${#selected_path_entries[@]} -gt 0 ]; then
        local pentry pglob nglobs palias ng gi ip
        local -a nglob_arr pf_args
        for pentry in "${selected_path_entries[@]}"; do
            # peco/pparser are unused here (dispatch happens later); discard them.
            IFS='|' read -r pglob nglobs _ _ palias <<< "$pentry"
            pf_args=( "$SEARCH_DIR" -path "$pglob" '(' )
            IFS=',' read -ra nglob_arr <<< "$nglobs"
            gi=0
            for ng in "${nglob_arr[@]}"; do
                [ "$gi" -gt 0 ] && pf_args+=( -o )
                pf_args+=( -name "$ng" )
                gi=$((gi + 1))
            done
            pf_args+=( ')' -type f )
            for ip in "${CONFIG_IGNORE_PATHS[@]}"; do
                pf_args+=( ! -path "*/$ip/*" )
            done
            local pfound
            pfound=$(find "${pf_args[@]}")
            if [ -n "$pfound" ]; then
                if [ -z "$TEMP_LOCKFILES" ]; then
                    TEMP_LOCKFILES="$pfound"
                else
                    TEMP_LOCKFILES="$TEMP_LOCKFILES
$pfound"
                fi
            fi
        done
    fi

    # Filter using git check-ignore (same behavior as before)
    if git rev-parse --git-dir > /dev/null 2>&1; then
        LOCKFILES=""
        local file
        while IFS= read -r file; do
            if ! git check-ignore -q "$file" 2>/dev/null; then
                if [ -z "$LOCKFILES" ]; then
                    LOCKFILES="$file"
                else
                    LOCKFILES="$LOCKFILES
$file"
                fi
            fi
        done <<< "$TEMP_LOCKFILES"
    else
        LOCKFILES="$TEMP_LOCKFILES"
    fi

    # ---- Find package.json files ----
    if [ "$only_lockfiles" = false ]; then
        local pj_args=( "$SEARCH_DIR" -name "package.json" -type f )
        local ignore_path2
        for ignore_path2 in "${CONFIG_IGNORE_PATHS[@]}"; do
            pj_args+=( ! -path "*/$ignore_path2/*" )
        done
        local TEMP_FILES
        TEMP_FILES=$(find "${pj_args[@]}")

        if git rev-parse --git-dir > /dev/null 2>&1; then
            PACKAGE_JSON_FILES=""
            local pfile
            while IFS= read -r pfile; do
                if ! git check-ignore -q "$pfile" 2>/dev/null; then
                    if [ -z "$PACKAGE_JSON_FILES" ]; then
                        PACKAGE_JSON_FILES="$pfile"
                    else
                        PACKAGE_JSON_FILES="$PACKAGE_JSON_FILES
$pfile"
                    fi
                fi
            done <<< "$TEMP_FILES"
        else
            PACKAGE_JSON_FILES="$TEMP_FILES"
        fi
    else
        PACKAGE_JSON_FILES=""
    fi

    # ---- Record detected ecosystems ----
    if [ -n "$LOCKFILES" ]; then
        local lfile b e _pe
        while IFS= read -r lfile; do
            [ -z "$lfile" ] && continue
            b=$(basename "$lfile")
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

main() {
    local use_default=true
    local use_config=true
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

    # Parse command line arguments
    local current_csv_columns=""
    while [[ $# -gt 0 ]]; do
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
                use_default=false
                use_config=false
                shift 2
                ;;
            --default-source-ghsa)
                # Record intent; the feed is resolved per detected ecosystem
                # after project discovery (see the source-loading section).
                default_feeds="ghsa"
                use_default=false
                use_config=false
                use_default_ghsa=true
                shift
                ;;
            --default-source-osv)
                default_feeds="osv"
                use_default=false
                use_config=false
                shift
                ;;
            --default-source-ghsa-osv)
                default_feeds="ghsa osv"
                use_default=false
                use_config=false
                shift
                ;;
            -f|--format)
                # Format for the previous URL
                if [ ${#custom_sources[@]} -gt 0 ]; then
                    local last_idx=$((${#custom_sources[@]} - 1))
                    local last_source="${custom_sources[$last_idx]}"
                    local url="${last_source%|*}"
                    custom_sources[$last_idx]="$url|$2"
                fi
                shift 2
                ;;
            --csv-columns)
                current_csv_columns="$2"
                # Apply columns to the last source if any
                if [ ${#custom_sources[@]} -gt 0 ]; then
                    local last_idx=$((${#custom_sources[@]} - 1))
                    local last_source="${custom_sources[$last_idx]}"
                    local url="${last_source%|*}"
                    local format="${last_source#*|}"
                    custom_sources[$last_idx]="$url|$format|$current_csv_columns"
                fi
                current_csv_columns=""
                shift 2
                ;;
            -c|--config)
                custom_config="$2"
                use_default=false
                shift 2
                ;;
            --no-config)
                use_config=false
                use_default=false
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
            --export-json)
                export_json_file="${2:-vulnerabilities.json}"
                shift 2
                ;;
            --export-csv)
                export_csv_file="${2:-vulnerabilities.csv}"
                shift 2
                ;;
            --fetch-all)
                # Optional DIR argument (default: data). Generates GHSA + OSV
                # feeds for ALL supported ecosystems.
                fetch_all "$2"
                exit 0
                ;;
            --fetch-osv)
                # Optional argument:
                #   (none)            -> all ecosystems into data/
                #   comma/space list  -> those ecosystems into data/ (e.g. pypi,go)
                #   legacy file path  -> npm feed into that file's directory
                case "${2:-}" in
                    ""|-*) fetch_osv ;;
                    */*|*.purl) FEED_OUTPUT_DIR="$(dirname "$2")" fetch_osv npm ;;
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"; fetch_osv "${_fetch_ecos[@]}" ;;
                esac
                exit 0
                ;;
            --fetch-ghsa)
                # Same argument semantics as --fetch-osv (single clone, all ecos).
                case "${2:-}" in
                    ""|-*) fetch_ghsa ;;
                    */*|*.purl) FEED_OUTPUT_DIR="$(dirname "$2")" fetch_ghsa npm ;;
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"; fetch_ghsa "${_fetch_ecos[@]}" ;;
                esac
                exit 0
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
            -*)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
            *)
                # Positional argument - treat as target path
                if [ -z "$target_path" ]; then
                    target_path="$1"
                    shift
                else
                    echo -e "${RED}❌ Error: Multiple target paths specified${NC}"
                    echo "Use --help for usage information"
                    exit 1
                fi
                ;;
        esac
    done

    # Validate mutually exclusive options
    if [ "$only_package_json" = true ] && [ "$only_lockfiles" = true ]; then
        echo -e "${RED}❌ Error: --only-package-json and --only-lockfiles are mutually exclusive${NC}"
        echo "Use --help for usage information"
        exit 1
    fi

    # Validate lockfile-types only makes sense with lockfiles
    if [ -n "$lockfile_types" ] && [ "$only_package_json" = true ]; then
        echo -e "${RED}❌ Error: --lockfile-types cannot be used with --only-package-json${NC}"
        echo "Use --help for usage information"
        exit 1
    fi

    # Validate --ecosystem against the supported purl types
    case "$ecosystem" in
        npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions)
            ;;
        *)
            echo -e "${RED}❌ Error: Unsupported ecosystem '$ecosystem'${NC}"
            echo "Valid ecosystems: npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions"
            exit 1
            ;;
    esac

    # Build the ecosystem lookup tables from the registry (single source of
    # truth for discovery, dispatch and default-feed resolution).
    build_ecosystem_tables

    # Validate the --ecosystems feed-loading override (aliases or purl types).
    if [ -n "$cli_ecosystems" ]; then
        validate_ecosystems_list "$cli_ecosystems" || exit 1
    fi

    check_dependencies

    # If --package-name is specified, create a virtual PURL source
    if [ -n "$name" ]; then
        # Create a temporary PURL file
        local temp_purl_file=$(mktemp)
        trap "rm -f $temp_purl_file" EXIT

        # Build the PURL line: pkg:<ecosystem>/package-name@version
        if [ -n "$package_version" ]; then
            echo "pkg:${ecosystem}/$name@$package_version" > "$temp_purl_file"
        else
            # If no version specified, use a placeholder
            # The actual vulnerable versions will come from the loaded sources
            echo "pkg:${ecosystem}/$name@*" > "$temp_purl_file"
        fi

        # Add this PURL file as a source
        custom_sources+=("$temp_purl_file|purl|")
        use_config=false

        # Explicit package check: seed detection with the chosen ecosystem so
        # its default feed is resolved even if no project files are found.
        DETECTED_ECOSYSTEMS["$ecosystem"]=1
    fi

    echo "╔════════════════════════════════════════════════════╗"
    echo "║       Package Vulnerability Checker                ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""

    # Fetch packages from GitHub if requested
    if [ "$use_github" = true ]; then
        fetch_github_packages || exit 1
        
        # If --github-only, exit after fetching
        if [ "$GITHUB_ONLY" = true ]; then
            echo -e "${GREEN}✅ GitHub packages fetched successfully. Use without --github-only to analyze.${NC}"
            exit 0
        fi
    fi

    # Discover project files and detect ecosystems BEFORE loading feeds, so we
    # only pull the default feeds the detected ecosystems actually need. This
    # step is silent; the results are printed/analyzed after the lookup build.
    discover_project_files

    # Load data sources
    local sources_loaded=false

    # 1. Config file first (may also set CONFIG_ECOSYSTEMS for feed override)
    if [ "$use_config" = true ]; then
        local config_to_use="${custom_config:-$CONFIG_FILE}"
        if load_config_file "$config_to_use"; then
            sources_loaded=true
        fi
    fi

    # 2. Explicit --source entries load unconditionally (no ecosystem filtering)
    if [ ${#custom_sources[@]} -gt 0 ]; then
        for source in "${custom_sources[@]}"; do
            IFS='|' read -r url format columns <<< "$source"
            load_data_source "$url" "$format" "Custom Source" "$columns"
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

        # Ecosystems to load feeds for: --ecosystems > config > auto-detected.
        local feed_ecos
        feed_ecos=$(resolve_feed_ecosystems "$cli_ecosystems")

        local eco feed feed_file feed_path feed_label
        for eco in $feed_ecos; do
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
                    load_data_source "$feed_path" "purl" "Default ${feed_label} Source" ""
                    sources_loaded=true
                else
                    echo -e "${YELLOW}⚠️  Warning: Unable to find ${feed} feed for ${eco} (${feed_file})${NC}"
                fi
            done
        done
    fi

    if [ "$sources_loaded" = false ]; then
        echo -e "${RED}❌ Error: Unable to find any vulnerability data source${NC}"
        echo ""
        echo "By default, package-checker uses the built-in GHSA feed."
        echo "If you see this message, no source could be found or loaded."
        echo ""
        echo "Tried the following locations for each detected ecosystem:"
        echo "  - Homebrew: \$(brew --prefix)/share/package-checker/data/"
        echo "  - Local: ./data/"
        echo "  - Docker: /app/data/"
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
        exit 1
    fi

    # Count total packages - OPTIMIZED: use associative array for O(1) uniqueness check
    local total_packages=0

    # First check if lookup tables have data (from CSV, PURL, or JSON)
    local lookup_count=0
    if [ ${#VULN_EXACT_LOOKUP[@]} -gt 0 ] || [ ${#VULN_RANGE_LOOKUP[@]} -gt 0 ]; then
        # OPTIMIZED: Use associative array to count unique packages (much faster than sort -u)
        declare -A unique_pkgs_temp
        for pkg in "${!VULN_EXACT_LOOKUP[@]}"; do
            unique_pkgs_temp["$pkg"]=1
        done
        for pkg in "${!VULN_RANGE_LOOKUP[@]}"; do
            unique_pkgs_temp["$pkg"]=1
        done
        lookup_count=${#unique_pkgs_temp[@]}
        unset unique_pkgs_temp
    fi

    # Also check VULN_DATA (may have JSON data not yet in lookup tables)
    local json_count=0
    if [ -n "$VULN_DATA" ] && [ "$VULN_DATA" != "{}" ]; then
        json_count=$(json_object_length "$VULN_DATA")
    fi

    # Use the maximum of the two counts (they should converge after build_vulnerability_lookup)
    if [ $lookup_count -gt $json_count ]; then
        total_packages=$lookup_count
    else
        total_packages=$json_count
    fi
    
    echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages${NC}"

    # If there are no vulnerability entries loaded, stop early — nothing to scan
    if [ "$total_packages" -eq 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  No vulnerability data loaded. Nothing to scan, exiting.${NC}"
        exit 0
    fi
    
    # Build vulnerability lookup tables for fast O(1) checking (if not already built)
    if [ "$VULN_LOOKUP_BUILT" != true ]; then
        echo -e "${BLUE}⚡ Building vulnerability lookup tables...${NC}"
        build_vulnerability_lookup
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
            lockname=$(basename "$lockfile")
            local lock_parser="${LOCKFILE_PARSER[$lockname]:-}"
            if [ -n "$lock_parser" ]; then
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
    if [ -z "$PACKAGE_JSON_FILES" ]; then
        if [ "$only_lockfiles" = true ]; then
            echo "   ⏩ Skipping package.json files (--only-lockfiles specified)"
        else
            echo "   ℹ️  No package.json files found"
        fi
    else
        PACKAGE_COUNT=$(echo "$PACKAGE_JSON_FILES" | wc -l | tr -d ' ')
        echo "📦 Analyzing $PACKAGE_COUNT package.json file(s)..."
        
        # Build regex pattern of dependency types to match
        local dep_types_pattern=$(printf '%s|' "${CONFIG_DEPENDENCY_TYPES[@]}")
        dep_types_pattern="${dep_types_pattern%|}"  # Remove trailing |
        
        while IFS= read -r package_file; do
            # Track vulnerabilities found in this file
            local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

            # Use awk to extract all dependencies efficiently
            local deps
            deps=$(awk -v dep_pattern="$dep_types_pattern" '
            BEGIN { in_deps=0; depth=0 }
            {
                line = $0

                # Check for dependency section start
                if (match(line, "\"(" dep_pattern ")\"[[:space:]]*:[[:space:]]*\\{")) {
                    in_deps = 1
                    depth = 1
                    # Handle inline content on same line
                    idx = index(line, "{")
                    if (idx > 0) line = substr(line, idx + 1)
                }

                if (in_deps) {
                    # Count braces
                    for (i = 1; i <= length(line); i++) {
                        c = substr(line, i, 1)
                        if (c == "{") depth++
                        else if (c == "}") depth--
                    }

                    # Extract "package": "version" patterns
                    while (match(line, /"([^"]+)"[[:space:]]*:[[:space:]]*"([^"]+)"/)) {
                        temp = substr(line, RSTART, RLENGTH)
                        # Extract package name
                        p1 = index(temp, "\"") + 1
                        p2 = index(substr(temp, p1), "\"") + p1 - 2
                        pkg = substr(temp, p1, p2 - p1 + 1)

                        # Extract version
                        rest = substr(temp, p2 + 2)
                        v1 = index(rest, "\"") + 1
                        v2 = index(substr(rest, v1), "\"") + v1 - 2
                        ver = substr(rest, v1, v2 - v1 + 1)

                        # Skip non-version specifiers (workspace, file, link, npm alias, etc.)
                        if (ver ~ /^(workspace|file|link|npm):/ || ver == "*" || ver == "latest") {
                            line = substr(line, RSTART + RLENGTH)
                            continue
                        }

                        # Clean version (remove ^, ~, >=, <, etc.)
                        gsub(/^[\^~>=<]+/, "", ver)
                        gsub(/[[:space:]].*/, "", ver)

                        if (pkg != "" && ver != "") {
                            print pkg "|" ver
                        }

                        line = substr(line, RSTART + RLENGTH)
                    }

                    if (depth <= 0) {
                        in_deps = 0
                        depth = 0
                    }
                }
            }
            ' "$package_file" 2>/dev/null | sort -u)

            # Check each dependency against vulnerability database
            while IFS='|' read -r pkg_name version; do
                [ -z "$pkg_name" ] || [ -z "$version" ] && continue
                # Use O(1) lookup instead of json_has_key (probe eco + wildcard namespaces)
                if [ -n "${VULN_EXACT_LOOKUP[npm:$pkg_name]+x}" ] || [ -n "${VULN_RANGE_LOOKUP[npm:$pkg_name]+x}" ] || [ -n "${VULN_EXACT_LOOKUP[*:$pkg_name]+x}" ] || [ -n "${VULN_RANGE_LOOKUP[*:$pkg_name]+x}" ]; then
                    check_vulnerability "npm" "$pkg_name" "$version" "$package_file" || true
                fi
            done <<< "$deps"

            # Check if vulnerabilities were found in this file
            local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
            if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
                echo -e "${GREEN}✓ [$package_file] No vulnerabilities found${NC}"
            fi
        done <<< "$PACKAGE_JSON_FILES"
    fi
    
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

            local has_metadata=false

            # Display all advisories from VULN_ADVISORIES if available
            if [ -n "${VULN_ADVISORIES[$pkg]+x}" ] && [ -n "${VULN_ADVISORIES[$pkg]}" ]; then
                local advisories_str="${VULN_ADVISORIES[$pkg]}"
                # Split by || to get individual advisories
                while [ -n "$advisories_str" ]; do
                    local advisory="${advisories_str%%||*}"
                    if [ "$advisory" = "$advisories_str" ]; then
                        advisories_str=""  # Last entry
                    else
                        advisories_str="${advisories_str#*||}"
                    fi
                    # Parse advisory: severity;ghsa;cve;source;fix
                    IFS=';' read -r severity ghsa cve adv_source fix_version <<< "$advisory"

                    if [ -n "$severity" ]; then
                        local severity_color=""
                        case "$severity" in
                            critical) severity_color="${RED}" ;;
                            high) severity_color="${YELLOW}" ;;
                            medium) severity_color="${BLUE}" ;;
                            low) severity_color="${NC}" ;;
                            *) severity_color="${NC}" ;;
                        esac
                        echo -e "      ${severity_color}Severity: $severity${NC}"
                        has_metadata=true
                    fi

                    if [ -n "$ghsa" ]; then
                        if [ "$adv_source" = "ghsa" ]; then
                            echo -e "      ${BLUE}GHSA: $ghsa (https://github.com/advisories/$ghsa)${NC}"
                        elif [ "$adv_source" = "osv" ]; then
                            echo -e "      ${BLUE}GHSA: $ghsa (https://osv.dev/vulnerability/$ghsa)${NC}"
                        else
                            echo -e "      ${BLUE}GHSA: $ghsa${NC}"
                        fi
                        has_metadata=true
                    fi

                    if [ -n "$cve" ]; then
                        echo -e "      ${BLUE}CVE: $cve (https://nvd.nist.gov/vuln/detail/$cve)${NC}"
                        has_metadata=true
                    fi

                    if [ -n "$adv_source" ]; then
                        echo -e "      ${BLUE}Source: $adv_source${NC}"
                        has_metadata=true
                    fi

                    if [ -n "$fix_version" ]; then
                        echo -e "      ${GREEN}Fix: upgrade to >= $fix_version${NC}"
                        has_metadata=true
                    fi
                done
            else
                # Fallback to VULN_METADATA_* arrays (for parsers without per-range metadata)
                # meta_key is the group key (eco:name@version); strip at LAST '@' for name (scoped-safe)
                local meta_key="$pkg"
                local pkg_name_only="${pkg%@*}"
                local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name_only]}}"
                local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name_only]}}"
                local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name_only]}}"
                local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name_only]}}"
                local fix="${VULN_METADATA_FIX[$meta_key]:-${VULN_METADATA_FIX[$pkg_name_only]}}"

                if [ -n "$severity" ]; then
                    local severity_color=""
                    case "$severity" in
                        critical) severity_color="${RED}" ;;
                        high) severity_color="${YELLOW}" ;;
                        medium) severity_color="${BLUE}" ;;
                        low) severity_color="${NC}" ;;
                        *) severity_color="${NC}" ;;
                    esac
                    echo -e "      ${severity_color}Severity: $severity${NC}"
                    has_metadata=true
                fi

                if [ -n "$ghsa" ]; then
                    if [ "$source" = "ghsa" ]; then
                        echo -e "      ${BLUE}GHSA: $ghsa (https://github.com/advisories/$ghsa)${NC}"
                    elif [ "$source" = "osv" ]; then
                        echo -e "      ${BLUE}GHSA: $ghsa (https://osv.dev/vulnerability/$ghsa)${NC}"
                    else
                        echo -e "      ${BLUE}GHSA: $ghsa${NC}"
                    fi
                    has_metadata=true
                fi

                if [ -n "$cve" ]; then
                    echo -e "      ${BLUE}CVE: $cve (https://nvd.nist.gov/vuln/detail/$cve)${NC}"
                    has_metadata=true
                fi

                if [ -n "$source" ]; then
                    echo -e "      ${BLUE}Source: $source${NC}"
                    has_metadata=true
                fi

                if [ -n "$fix" ]; then
                    echo -e "      ${GREEN}Fix: upgrade to >= $fix${NC}"
                    has_metadata=true
                fi
            fi

            if [ "$has_metadata" = true ]; then
                echo ""
            fi

            IFS='|' read -ra files <<< "${pkg_files[$pkg]}"
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

            # Determine repository full name
            local repo_full_name=""
            if [ -n "$GITHUB_REPO" ]; then
                repo_full_name="$GITHUB_REPO"
            elif [ -n "$GITHUB_ORG" ]; then
                # For org scanning, we need to handle multiple repos
                # Get the first repo from the packages directory
                local first_repo=""
                for vuln in "${VULNERABLE_PACKAGES[@]}"; do
                    IFS='|' read -r file eco pkg <<< "$vuln"
                    if [[ "$file" =~ packages/([^/]+)/ ]]; then
                        first_repo="${BASH_REMATCH[1]}"
                        break
                    fi
                done
                if [ -n "$first_repo" ]; then
                    repo_full_name="${GITHUB_ORG}/${first_repo}"
                fi
            fi

            if [ -z "$repo_full_name" ]; then
                echo -e "${YELLOW}⚠️  Cannot determine repository. Use --github-repo or --github-org${NC}"
            else
                # Group vulnerabilities by package name (not version)
                # Structure: pkg_vulns[package_name] = "version1|severity|ghsa|cve|source|files\nversion2|..."
                declare -A pkg_vulns
                declare -A pkg_version_seen
                declare -A pkg_eco

                for vuln in "${VULNERABLE_PACKAGES[@]}"; do
                    IFS='|' read -r file eco pkg_with_version <<< "$vuln"

                    # Extract package name and version (scoped-safe: split at LAST '@')
                    local pkg_name="${pkg_with_version%@*}"
                    local pkg_version="${pkg_with_version##*@}"

                    # Record the ecosystem so the remediation block can print the
                    # commands for THIS package's stack (npm/cargo/pypi/…).
                    pkg_eco[$pkg_name]="$eco"

                    # Get metadata (namespaced by ecosystem)
                    local meta_key="${eco}:${pkg_with_version}"
                    local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name]:-unknown}}"
                    local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name]:--}}"
                    local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name]:--}}"
                    local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name]:--}}"

                    # Create a unique key for this version to avoid duplicates
                    local version_key="${pkg_name}@${pkg_version}"

                    if [ -z "${pkg_version_seen[$version_key]}" ]; then
                        pkg_version_seen[$version_key]=1

                        # Build vulnerability entry: version|severity|ghsa|cve|source|files
                        local vuln_entry="${pkg_version}|${severity}|${ghsa}|${cve}|${source}|${file}"

                        if [ -z "${pkg_vulns[$pkg_name]}" ]; then
                            pkg_vulns[$pkg_name]="$vuln_entry"
                        else
                            pkg_vulns[$pkg_name]="${pkg_vulns[$pkg_name]}"$'\n'"$vuln_entry"
                        fi
                    else
                        # Same version seen again, just add the file to existing entry
                        local updated_vulns=""
                        while IFS= read -r line; do
                            local line_version="${line%%|*}"
                            if [ "$line_version" = "$pkg_version" ]; then
                                # Append file to this entry
                                line="${line},${file}"
                            fi
                            if [ -z "$updated_vulns" ]; then
                                updated_vulns="$line"
                            else
                                updated_vulns="${updated_vulns}"$'\n'"$line"
                            fi
                        done <<< "${pkg_vulns[$pkg_name]}"
                        pkg_vulns[$pkg_name]="$updated_vulns"
                    fi
                done

                # Create one issue per package
                local issues_created=0
                local unique_packages=$(printf '%s\n' "${!pkg_vulns[@]}" | sort -u)
                local total_packages=$(echo "$unique_packages" | wc -l | tr -d ' ')

                echo -e "${BLUE}Found ${total_packages} unique vulnerable package(s)${NC}"
                echo ""

                for pkg_name in $unique_packages; do
                    [ -z "$pkg_name" ] && continue

                    local vuln_data="${pkg_vulns[$pkg_name]}"
                    local vuln_count=$(echo "$vuln_data" | wc -l | tr -d ' ')

                    echo -e "${BLUE}📦 ${pkg_name}${NC} (${vuln_count} vulnerability/ies)"

                    # Determine highest severity for the title
                    local max_severity="unknown"
                    local has_critical=false
                    local has_high=false
                    local has_medium=false
                    local has_low=false

                    while IFS='|' read -r ver sev ghsa cve src files; do
                        case "${sev,,}" in
                            critical) has_critical=true ;;
                            high) has_high=true ;;
                            medium) has_medium=true ;;
                            low) has_low=true ;;
                        esac
                    done <<< "$vuln_data"

                    if [ "$has_critical" = true ]; then
                        max_severity="CRITICAL"
                    elif [ "$has_high" = true ]; then
                        max_severity="HIGH"
                    elif [ "$has_medium" = true ]; then
                        max_severity="MEDIUM"
                    elif [ "$has_low" = true ]; then
                        max_severity="LOW"
                    fi

                    # Build issue title with severity indicator
                    local severity_emoji=""
                    case "$max_severity" in
                        CRITICAL) severity_emoji="🔴" ;;
                        HIGH) severity_emoji="🟠" ;;
                        MEDIUM) severity_emoji="🟡" ;;
                        LOW) severity_emoji="🟢" ;;
                        *) severity_emoji="⚪" ;;
                    esac

                    local issue_title="${severity_emoji} Security: ${vuln_count} vulnerabilit"
                    if [ "$vuln_count" -eq 1 ]; then
                        issue_title="${issue_title}y in \`${pkg_name}\`"
                    else
                        issue_title="${issue_title}ies in \`${pkg_name}\`"
                    fi

                    if [ "$max_severity" != "unknown" ]; then
                        issue_title="${issue_title} [${max_severity}]"
                    fi

                    # Build issue body
                    local issue_body=""
                    issue_body+="## 🔒 Security Vulnerabilities in \`${pkg_name}\`"$'\n\n'

                    # Summary table
                    issue_body+="### 📊 Summary"$'\n\n'
                    issue_body+="| Metric | Count |"$'\n'
                    issue_body+="|--------|-------|"$'\n'
                    issue_body+="| **Total Vulnerabilities** | ${vuln_count} |"$'\n'

                    # Count by severity
                    local crit_cnt=0 high_cnt=0 med_cnt=0 low_cnt=0 unk_cnt=0
                    while IFS='|' read -r ver sev ghsa cve src files; do
                        case "${sev,,}" in
                            critical) crit_cnt=$((crit_cnt + 1)) ;;
                            high) high_cnt=$((high_cnt + 1)) ;;
                            medium) med_cnt=$((med_cnt + 1)) ;;
                            low) low_cnt=$((low_cnt + 1)) ;;
                            *) unk_cnt=$((unk_cnt + 1)) ;;
                        esac
                    done <<< "$vuln_data"

                    [ "$crit_cnt" -gt 0 ] && issue_body+="| 🔴 Critical | ${crit_cnt} |"$'\n'
                    [ "$high_cnt" -gt 0 ] && issue_body+="| 🟠 High | ${high_cnt} |"$'\n'
                    [ "$med_cnt" -gt 0 ] && issue_body+="| 🟡 Medium | ${med_cnt} |"$'\n'
                    [ "$low_cnt" -gt 0 ] && issue_body+="| 🟢 Low | ${low_cnt} |"$'\n'
                    [ "$unk_cnt" -gt 0 ] && issue_body+="| ⚪ Unknown | ${unk_cnt} |"$'\n'

                    issue_body+=$'\n'"---"$'\n\n'
                    issue_body+="### 🔍 Vulnerability Details"$'\n\n'

                    # Detail each vulnerability
                    local vuln_num=0
                    while IFS='|' read -r ver sev ghsa cve src files; do
                        [ -z "$ver" ] && continue
                        vuln_num=$((vuln_num + 1))

                        # Severity badge
                        local sev_badge="⚪ Unknown"
                        case "${sev,,}" in
                            critical) sev_badge="🔴 **CRITICAL**" ;;
                            high) sev_badge="🟠 **HIGH**" ;;
                            medium) sev_badge="🟡 **MEDIUM**" ;;
                            low) sev_badge="🟢 **LOW**" ;;
                        esac

                        issue_body+="#### ${vuln_num}. Version \`${ver}\`"$'\n\n'
                        issue_body+="| Property | Value |"$'\n'
                        issue_body+="|----------|-------|"$'\n'
                        issue_body+="| **Severity** | ${sev_badge} |"$'\n'

                        if [ -n "$ghsa" ] && [ "$ghsa" != "-" ]; then
                            issue_body+="| **GHSA** | [${ghsa}](https://github.com/advisories/${ghsa}) |"$'\n'
                        fi

                        if [ -n "$cve" ] && [ "$cve" != "-" ]; then
                            issue_body+="| **CVE** | [${cve}](https://nvd.nist.gov/vuln/detail/${cve}) |"$'\n'
                        fi

                        if [ -n "$src" ] && [ "$src" != "-" ]; then
                            issue_body+="| **Source** | ${src} |"$'\n'
                        fi

                        issue_body+=$'\n'

                        # Affected files
                        if [ -n "$files" ] && [ "$files" != "-" ]; then
                            issue_body+="<details>"$'\n'
                            issue_body+="<summary>📁 Affected files</summary>"$'\n\n'
                            local file_list=""
                            IFS=',' read -ra file_array <<< "$files"
                            for f in "${file_array[@]}"; do
                                [ -n "$f" ] && file_list+="- \`${f}\`"$'\n'
                            done
                            issue_body+="${file_list}"$'\n'
                            issue_body+="</details>"$'\n\n'
                        fi

                        issue_body+="---"$'\n\n'
                    done <<< "$vuln_data"

                    # Recommendations — ecosystem-aware fix + verify commands.
                    local rec_eco="${pkg_eco[$pkg_name]:-npm}"
                    issue_body+="### ✅ Recommendations"$'\n\n'
                    issue_body+="1. **Update the package** to the latest patched version:"$'\n'
                    issue_body+="   \`\`\`bash"$'\n'
                    issue_body+="$(fix_commands_for_eco "$rec_eco" "$pkg_name" "   ")"$'\n'
                    issue_body+="   \`\`\`"$'\n\n'
                    issue_body+="2. **Check for breaking changes** before updating major versions"$'\n\n'
                    issue_body+="3. **Run a security audit** after updating:"$'\n'
                    issue_body+="   \`\`\`bash"$'\n'
                    issue_body+="   $(verify_command_for_eco "$rec_eco")"$'\n'
                    issue_body+="   \`\`\`"$'\n\n'
                    issue_body+="4. **Review the advisories** linked above for specific remediation steps"$'\n\n'
                    issue_body+="---"$'\n\n'
                    issue_body+="*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"

                    # Create the issue
                    if create_github_issue "$repo_full_name" "$issue_title" "$issue_body" "security,vulnerability,dependencies"; then
                        issues_created=$((issues_created + 1))
                    fi

                    sleep 1  # Rate limiting
                    echo ""
                done

                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo -e "${GREEN}✅ Created ${issues_created} issue(s) for ${total_packages} package(s)${NC}"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            fi
        fi

        # Create a single consolidated GitHub issue if requested
        if [ "$CREATE_SINGLE_ISSUE" = true ]; then
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -e "${BLUE}📝 Creating Single Consolidated GitHub Issue${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""

            # Determine repository full name
            local repo_full_name=""
            if [ -n "$GITHUB_REPO" ]; then
                repo_full_name="$GITHUB_REPO"
            elif [ -n "$GITHUB_ORG" ]; then
                local first_repo=""
                for vuln in "${VULNERABLE_PACKAGES[@]}"; do
                    IFS='|' read -r file eco pkg <<< "$vuln"
                    if [[ "$file" =~ packages/([^/]+)/ ]]; then
                        first_repo="${BASH_REMATCH[1]}"
                        break
                    fi
                done
                if [ -n "$first_repo" ]; then
                    repo_full_name="${GITHUB_ORG}/${first_repo}"
                fi
            fi

            if [ -z "$repo_full_name" ]; then
                echo -e "${YELLOW}⚠️  Cannot determine repository. Use --github-repo or --github-org${NC}"
            else
                # Count unique packages and total vulnerabilities (name is field 3, scoped-safe)
                local unique_packages=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | cut -d'|' -f3 | sed 's/@[^@]*$//' | sort -u)
                local unique_pkg_count=$(echo "$unique_packages" | wc -l | tr -d ' ')
                local total_vulns=${#VULNERABLE_PACKAGES[@]}

                # Count severities across all vulnerabilities
                local global_critical=0 global_high=0 global_medium=0 global_low=0 global_unknown=0

                for vuln in "${VULNERABLE_PACKAGES[@]}"; do
                    IFS='|' read -r file eco pkg_with_version <<< "$vuln"
                    local pkg_name="${pkg_with_version%@*}"
                    local meta_key="${eco}:${pkg_with_version}"
                    local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name]:-unknown}}"

                    case "${severity,,}" in
                        critical) global_critical=$((global_critical + 1)) ;;
                        high) global_high=$((global_high + 1)) ;;
                        medium) global_medium=$((global_medium + 1)) ;;
                        low) global_low=$((global_low + 1)) ;;
                        *) global_unknown=$((global_unknown + 1)) ;;
                    esac
                done

                # Determine highest severity for the title
                local max_severity="UNKNOWN"
                local severity_emoji="⚪"
                if [ "$global_critical" -gt 0 ]; then
                    max_severity="CRITICAL"; severity_emoji="🔴"
                elif [ "$global_high" -gt 0 ]; then
                    max_severity="HIGH"; severity_emoji="🟠"
                elif [ "$global_medium" -gt 0 ]; then
                    max_severity="MEDIUM"; severity_emoji="🟡"
                elif [ "$global_low" -gt 0 ]; then
                    max_severity="LOW"; severity_emoji="🟢"
                fi

                # Build issue title
                local issue_title="${severity_emoji} Security Report: ${total_vulns} vulnerabilities in ${unique_pkg_count} packages [${max_severity}]"

                # Build issue body
                local issue_body=""
                issue_body+="## 🔒 Security Vulnerability Report"$'\n\n'
                issue_body+="This issue contains a consolidated report of all security vulnerabilities detected in this repository."$'\n\n'

                # Global summary
                issue_body+="### 📊 Global Summary"$'\n\n'
                issue_body+="| Metric | Count |"$'\n'
                issue_body+="|--------|-------|"$'\n'
                issue_body+="| **Total Vulnerabilities** | ${total_vulns} |"$'\n'
                issue_body+="| **Affected Packages** | ${unique_pkg_count} |"$'\n'
                [ "$global_critical" -gt 0 ] && issue_body+="| 🔴 Critical | ${global_critical} |"$'\n'
                [ "$global_high" -gt 0 ] && issue_body+="| 🟠 High | ${global_high} |"$'\n'
                [ "$global_medium" -gt 0 ] && issue_body+="| 🟡 Medium | ${global_medium} |"$'\n'
                [ "$global_low" -gt 0 ] && issue_body+="| 🟢 Low | ${global_low} |"$'\n'
                [ "$global_unknown" -gt 0 ] && issue_body+="| ⚪ Unknown | ${global_unknown} |"$'\n'

                issue_body+=$'\n'"---"$'\n\n'

                # Group vulnerabilities by package
                declare -A single_pkg_vulns
                declare -A single_pkg_version_seen

                for vuln in "${VULNERABLE_PACKAGES[@]}"; do
                    IFS='|' read -r file eco pkg_with_version <<< "$vuln"
                    local pkg_name="${pkg_with_version%@*}"
                    local pkg_version="${pkg_with_version##*@}"
                    local meta_key="${eco}:${pkg_with_version}"
                    local severity="${VULN_METADATA_SEVERITY[$meta_key]:-${VULN_METADATA_SEVERITY[$pkg_name]:-unknown}}"
                    local ghsa="${VULN_METADATA_GHSA[$meta_key]:-${VULN_METADATA_GHSA[$pkg_name]:--}}"
                    local cve="${VULN_METADATA_CVE[$meta_key]:-${VULN_METADATA_CVE[$pkg_name]:--}}"
                    local source="${VULN_METADATA_SOURCE[$meta_key]:-${VULN_METADATA_SOURCE[$pkg_name]:--}}"

                    local version_key="${pkg_name}@${pkg_version}"

                    if [ -z "${single_pkg_version_seen[$version_key]}" ]; then
                        single_pkg_version_seen[$version_key]=1
                        local vuln_entry="${pkg_version}|${severity}|${ghsa}|${cve}|${source}|${file}"

                        if [ -z "${single_pkg_vulns[$pkg_name]}" ]; then
                            single_pkg_vulns[$pkg_name]="$vuln_entry"
                        else
                            single_pkg_vulns[$pkg_name]="${single_pkg_vulns[$pkg_name]}"$'\n'"$vuln_entry"
                        fi
                    else
                        local updated_vulns=""
                        while IFS= read -r line; do
                            local line_version="${line%%|*}"
                            if [ "$line_version" = "$pkg_version" ]; then
                                line="${line},${file}"
                            fi
                            if [ -z "$updated_vulns" ]; then
                                updated_vulns="$line"
                            else
                                updated_vulns="${updated_vulns}"$'\n'"$line"
                            fi
                        done <<< "${single_pkg_vulns[$pkg_name]}"
                        single_pkg_vulns[$pkg_name]="$updated_vulns"
                    fi
                done

                # Detail each package
                issue_body+="### 📦 Vulnerable Packages"$'\n\n'

                local pkg_num=0
                for pkg_name in $(printf '%s\n' "${!single_pkg_vulns[@]}" | sort); do
                    [ -z "$pkg_name" ] && continue
                    pkg_num=$((pkg_num + 1))

                    local vuln_data="${single_pkg_vulns[$pkg_name]}"
                    local vuln_count=$(echo "$vuln_data" | wc -l | tr -d ' ')

                    # Count package severities
                    local pkg_crit=0 pkg_high=0 pkg_med=0 pkg_low=0
                    while IFS='|' read -r ver sev ghsa cve src files; do
                        case "${sev,,}" in
                            critical) pkg_crit=$((pkg_crit + 1)) ;;
                            high) pkg_high=$((pkg_high + 1)) ;;
                            medium) pkg_med=$((pkg_med + 1)) ;;
                            low) pkg_low=$((pkg_low + 1)) ;;
                        esac
                    done <<< "$vuln_data"

                    # Package severity indicator
                    local pkg_sev_emoji="⚪"
                    if [ "$pkg_crit" -gt 0 ]; then pkg_sev_emoji="🔴"
                    elif [ "$pkg_high" -gt 0 ]; then pkg_sev_emoji="🟠"
                    elif [ "$pkg_med" -gt 0 ]; then pkg_sev_emoji="🟡"
                    elif [ "$pkg_low" -gt 0 ]; then pkg_sev_emoji="🟢"
                    fi

                    issue_body+="<details>"$'\n'
                    issue_body+="<summary>${pkg_sev_emoji} <strong>${pkg_name}</strong> (${vuln_count} vulnerabilities)</summary>"$'\n\n'

                    # Vulnerability table for this package
                    issue_body+="| Version | Severity | GHSA | CVE |"$'\n'
                    issue_body+="|---------|----------|------|-----|"$'\n'

                    while IFS='|' read -r ver sev ghsa cve src files; do
                        [ -z "$ver" ] && continue

                        local sev_badge="⚪ Unknown"
                        case "${sev,,}" in
                            critical) sev_badge="🔴 Critical" ;;
                            high) sev_badge="🟠 High" ;;
                            medium) sev_badge="🟡 Medium" ;;
                            low) sev_badge="🟢 Low" ;;
                        esac

                        local ghsa_link="-"
                        if [ -n "$ghsa" ] && [ "$ghsa" != "-" ]; then
                            ghsa_link="[${ghsa}](https://github.com/advisories/${ghsa})"
                        fi

                        local cve_link="-"
                        if [ -n "$cve" ] && [ "$cve" != "-" ]; then
                            cve_link="[${cve}](https://nvd.nist.gov/vuln/detail/${cve})"
                        fi

                        issue_body+="| \`${ver}\` | ${sev_badge} | ${ghsa_link} | ${cve_link} |"$'\n'
                    done <<< "$vuln_data"

                    issue_body+=$'\n'"**Affected files:**"$'\n'
                    while IFS='|' read -r ver sev ghsa cve src files; do
                        [ -z "$ver" ] && continue
                        IFS=',' read -ra file_array <<< "$files"
                        for f in "${file_array[@]}"; do
                            [ -n "$f" ] && issue_body+="- \`${f}\`"$'\n'
                        done
                    done <<< "$vuln_data"

                    issue_body+=$'\n'"</details>"$'\n\n'
                done

                # Recommendations — one remediation block per ecosystem present
                # in the findings (a polyglot repo gets npm + cargo + pypi + …).
                local present_ecos
                present_ecos=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | cut -d'|' -f2 | sort -u)
                issue_body+="---"$'\n\n'
                issue_body+="### ✅ Recommended Actions"$'\n\n'
                issue_body+="1. **Review each vulnerability** using the GHSA/CVE links above."$'\n'
                issue_body+="2. **Update the affected packages** to their latest patched versions. Commands per detected ecosystem:"$'\n\n'
                local rec_eco
                while IFS= read -r rec_eco; do
                    [ -z "$rec_eco" ] && continue
                    issue_body+="#### $(eco_display_name "$rec_eco")"$'\n\n'
                    issue_body+="\`\`\`bash"$'\n'
                    issue_body+="$(fix_commands_for_eco "$rec_eco" "<package-name>")"$'\n'
                    issue_body+="\`\`\`"$'\n\n'
                    issue_body+="Verify: \`$(verify_command_for_eco "$rec_eco")\`"$'\n\n'
                done <<< "$present_ecos"
                issue_body+="---"$'\n\n'
                issue_body+="*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"

                # Create the single consolidated issue
                echo -e "${BLUE}Creating consolidated security report...${NC}"
                if create_github_issue "$repo_full_name" "$issue_title" "$issue_body" "security,vulnerability,dependencies"; then
                    echo ""
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo -e "${GREEN}✅ Created 1 consolidated issue with ${total_vulns} vulnerabilities${NC}"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                else
                    echo ""
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo -e "${RED}❌ Failed to create consolidated issue${NC}"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                fi
            fi
        fi
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Export results if requested
    if [ -n "$export_json_file" ] && [ ${#VULNERABLE_PACKAGES[@]} -gt 0 ]; then
        echo ""
        export_vulnerabilities_json "$export_json_file"
    fi

    if [ -n "$export_csv_file" ] && [ ${#VULNERABLE_PACKAGES[@]} -gt 0 ]; then
        echo ""
        export_vulnerabilities_csv "$export_csv_file"
    fi

    exit $FOUND_VULNERABLE
}

# Run main function only when executed directly (allows `source script.sh` in unit tests)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
