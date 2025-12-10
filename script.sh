#!/usr/bin/env bash

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

set -e

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
VULN_LOOKUP_BUILT=false

# Configuration defaults (can be overridden by config file)
CONFIG_IGNORE_PATHS=("node_modules" ".yarn" ".git")
CONFIG_DEPENDENCY_TYPES=("dependencies" "devDependencies" "optionalDependencies" "peerDependencies")

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
    # - when a key exists in both, try to merge their vulnerability_version and vulnerability_version_range arrays
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
            local v1=$(json_get_array "$obj1" "vulnerability_version")
            local v2=$(json_get_array "$obj2" "vulnerability_version")
            local r1=$(json_get_array "$obj1" "vulnerability_version_range")
            local r2=$(json_get_array "$obj2" "vulnerability_version_range")

            add_items "$v1" "version"
            add_items "$v2" "version"
            add_items "$r1" "range"
            add_items "$r2" "range"

            # Build merged object JSON
            merged_obj="{"
            local has=false
            if [ ${#versions_list[@]} -gt 0 ]; then
                merged_obj+="\"vulnerability_version\":["
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
                merged_obj+="\"vulnerability_version_range\":["
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

# Help message
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

A tool to check Node.js projects for vulnerable packages against custom data sources.

OPTIONS:
    -h, --help              Show this help message
    -s, --source SOURCE     Data source path or URL (can be used multiple times)
    -f, --format FORMAT     Data format: json or csv (default: json)
    -c, --config FILE       Path to configuration file (default: .package-checker.config.json)
    --no-config             Skip loading configuration file
    --csv-columns COLS      CSV columns specification (e.g., "1,2" or "package_name,package_versions")
    --github-org ORG        GitHub organization to fetch package.json files from
    --github-repo REPO      GitHub repository to fetch package.json files from (format: owner/repo)
    --github-token TOKEN    GitHub personal access token (or use GITHUB_TOKEN env var)
    --github-output DIR     Output directory for fetched packages (default: ./packages)
    --github-only           Only fetch packages from GitHub, don't analyze local files
    
EXAMPLES:
    # Use configuration file
    $0
    
    # Use custom JSON source
    $0 --source https://example.com/vulns.json --format json
    
    # Use custom CSV source
    $0 --source https://example.com/vulns.csv --format csv
    
    # Use CSV with specific columns (package_name=1, package_versions=2)
    $0 --source data.csv --format csv --csv-columns "1,2"
    
    # Use CSV with column names
    $0 --source data.csv --format csv --csv-columns "package_name,package_versions"
    
    # Use multiple sources
    $0 --source https://example.com/vulns1.json --source https://example.com/vulns2.csv
    
    # Use configuration file
    $0 --config my-config.json

    # Fetch and analyze packages from a GitHub organization
    $0 --github-org myorg --github-token ghp_xxxx --source vulns.json

    # Fetch and analyze packages from a single GitHub repository
    $0 --github-repo owner/repo --github-token ghp_xxxx --source vulns.json

    # Use environment variables for GitHub
    GITHUB_ORG=myorg GITHUB_TOKEN=ghp_xxxx $0 --source vulns.json

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
      "columns": "package_name,package_versions",
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
    "vulnerability_version": ["1.0.0", "2.0.0"]
  }
}

CSV format (default: package,version):
package-name,1.0.0
package-name,2.0.0
another-package,3.0.0

CSV format with custom columns:
package_name,package_versions,sources
express,4.16.0,"datadog, helixguard"
lodash,4.17.19,"koi, reversinglabs"

Use --csv-columns to specify which columns to use:
--csv-columns "1,2"     # Use columns 1 and 2 (package_name, package_versions)
--csv-columns "package_name,package_versions"  # Use column names

EOF
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
    local target_files
    target_files=$(echo "$tree_response" | \
        grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"$//' | \
        grep -v 'node_modules' | \
        grep -E '(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|deno\.lock)$')
    
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
    
    # Search for multiple file types
    local all_files=""
    local search_terms=("package.json" "package-lock.json" "npm-shrinkwrap.json" "yarn.lock" "pnpm-lock.yaml" "bun.lock" "deno.lock")
    
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
# Output: JSON object with vulnerability_version and vulnerability_version_range arrays
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
        if (tolower(pkg) == "package" || tolower(pkg) == "package_name") next
        
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
                printf "\"vulnerability_version\":[%s]", pkg_versions[pkg]
                has_content = 1
            }
            
            if (pkg in pkg_ranges) {
                if (has_content) printf ","
                printf "\"vulnerability_version_range\":[%s]", pkg_ranges[pkg]
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
        if (tolower(pkg) == "package" || tolower(pkg) == "package_name") next
        
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
        # Output eval commands that MERGE with existing data instead of overwriting
        for (pkg in pkg_versions) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_versions[pkg]), escape_sq(pkg), escape_sq(pkg_versions[pkg])
        }
        for (pkg in pkg_ranges) {
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(pkg_ranges[pkg]), escape_sq(pkg), escape_sq(pkg_ranges[pkg])
        }
        # Output package count
        printf "CSV_PKG_COUNT=%d\n", pkg_count
    }
    '
}

# Alias for backward compatibility
parse_csv_default() {
    parse_csv_to_json "$1"
}

# Detect format from URL
detect_format_from_url() {
    local url="$1"
    local extension="${url##*.}"
    
    # Remove query parameters and fragments
    extension="${extension%%\?*}"
    extension="${extension%%\#*}"
    
    case "$extension" in
        json)
            echo "json"
            ;;
        csv)
            echo "csv"
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
            local eval_commands
            eval_commands=$(parse_csv_to_lookup_eval "$raw_data")

            # Extract package count before eval
            pkg_count=$(echo "$eval_commands" | grep -oE 'CSV_PKG_COUNT=[0-9]+' | cut -d= -f2)
            pkg_count=${pkg_count:-0}

            # Execute assignments directly into lookup tables (merges with existing data)
            eval "$eval_commands"

            # NOTE: Do NOT set VULN_LOOKUP_BUILT=true here!
            # This allows build_vulnerability_lookup() to still process JSON data
            # that was loaded from other sources into VULN_DATA

            # For compatibility, also generate minimal JSON (just for display/merge if needed)
            # But we skip this since we already have the data in lookup tables
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
    # Handles formats like: 1.0.0, 1.0.0-rc.1, 1.0.0-alpha, 1.0.0-rc-hash-date, etc.
    echo "$version" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/'
}

# Compare two semver versions
# Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
compare_versions() {
    local v1="$1"
    local v2="$2"
    
    # Extract base versions for comparison
    local base1=$(get_base_version "$v1")
    local base2=$(get_base_version "$v2")
    
    # Split into major.minor.patch
    local major1=$(echo "$base1" | cut -d. -f1)
    local minor1=$(echo "$base1" | cut -d. -f2)
    local patch1=$(echo "$base1" | cut -d. -f3)
    
    local major2=$(echo "$base2" | cut -d. -f1)
    local minor2=$(echo "$base2" | cut -d. -f2)
    local patch2=$(echo "$base2" | cut -d. -f3)
    
    # Default to 0 if empty
    major1=${major1:-0}
    minor1=${minor1:-0}
    patch1=${patch1:-0}
    major2=${major2:-0}
    minor2=${minor2:-0}
    patch2=${patch2:-0}
    
    # Compare major
    if [ "$major1" -lt "$major2" ]; then
        echo "-1"
        return
    elif [ "$major1" -gt "$major2" ]; then
        echo "1"
        return
    fi
    
    # Compare minor
    if [ "$minor1" -lt "$minor2" ]; then
        echo "-1"
        return
    elif [ "$minor1" -gt "$minor2" ]; then
        echo "1"
        return
    fi
    
    # Compare patch
    if [ "$patch1" -lt "$patch2" ]; then
        echo "-1"
        return
    elif [ "$patch1" -gt "$patch2" ]; then
        echo "1"
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
        echo "-1"  # pre-release < release
        return
    elif [ "$has_prerelease1" = false ] && [ "$has_prerelease2" = true ]; then
        echo "1"   # release > pre-release
        return
    fi
    
    echo "0"
}

# Check if a version is within a range
# Range format: ">1.0.0 <=2.0.0" or ">=1.0.0 <2.0.0" etc.
# Pre-release versions are included if their base version is within the range
version_in_range() {
    local version="$1"
    local range="$2"
    
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
        local cmp
        if [ "$is_prerelease" = true ]; then
            # Special handling for >= operator with pre-release
            # 19.0.0-rc is considered >= 19.0.0 (it's a pre-release OF 19.0.0)
            if [ "$operator" = ">=" ] && [ "$base_version" = "$range_version" ]; then
                cmp="0"  # Consider it equal for >= comparison
            else
                cmp=$(compare_versions "$version" "$range_version")
            fi
        else
            cmp=$(compare_versions "$version" "$range_version")
        fi
        
        case "$operator" in
            ">")
                if [ "$cmp" != "1" ]; then
                    return 1  # version is not > range_version
                fi
                ;;
            ">=")
                if [ "$cmp" = "-1" ]; then
                    return 1  # version is < range_version
                fi
                ;;
            "<")
                if [ "$cmp" != "-1" ]; then
                    return 1  # version is not < range_version
                fi
                ;;
            "<=")
                if [ "$cmp" = "1" ]; then
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
    local vulnerability_version="$2"
    
    # Exact match
    if [ "$installed_version" = "$vulnerability_version" ]; then
        return 0
    fi
    
    # Check if installed version is a pre-release of the vulnerable version
    # For example: "19.0.0-rc-xxx" should match "19.0.0"
    local installed_base=$(get_base_version "$installed_version")
    
    if [ "$installed_base" = "$vulnerability_version" ] && [ "$installed_version" != "$installed_base" ]; then
        # It's a pre-release version (has suffix) and base matches
        return 0
    fi
    
    return 1
}

# Build vulnerability lookup tables from VULN_DATA for O(1) lookups
# This parses the JSON once and stores in associative arrays
# OPTIMIZED: awk generates bash eval statements directly, avoiding slow bash loops
# NOTE: This function MERGES JSON data with existing lookup tables (e.g., from CSV)
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
                } else if (str == "vulnerability_version" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
                    in_ver = 1
                    in_range = 0
                } else if (str == "vulnerability_version_range" && match(rest, /^[[:space:]]*:[[:space:]]*\[/)) {
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
        # Output bash eval statements that MERGE with existing data
        for (pkg in exact_vers) {
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(exact_vers[pkg]), escape_sq(pkg), escape_sq(exact_vers[pkg])
        }
        for (pkg in range_vers) {
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(pkg), escape_sq(pkg), escape_sq(range_vers[pkg]), escape_sq(pkg), escape_sq(range_vers[pkg])
        }
    }
    ')

    # Execute all assignments at once (much faster than while-read loop)
    eval "$eval_commands"
    
    VULN_LOOKUP_BUILT=true
}

# Function to check if a package+version is vulnerable
# Uses pre-built lookup tables for O(1) access
check_vulnerability() {
    local package_name="$1"
    local version="$2"
    local source="$3"
    
    # Check if package exists in vulnerability database (O(1) lookup)
    if [ -z "${VULN_EXACT_LOOKUP[$package_name]+x}" ] && [ -z "${VULN_RANGE_LOOKUP[$package_name]+x}" ]; then
        return 1
    fi
    
    # Get vulnerable versions (already pipe-separated)
    local vulnerability_versions="${VULN_EXACT_LOOKUP[$package_name]:-}"
    local vulnerability_ranges="${VULN_RANGE_LOOKUP[$package_name]:-}"
    
    # Check exact version matches
    if [ -n "$vulnerability_versions" ]; then
        IFS='|' read -ra vers_array <<< "$vulnerability_versions"
        for vulnerability_ver in "${vers_array[@]}"; do
            [ -z "$vulnerability_ver" ] && continue
            if version_matches_vulnerable "$version" "$vulnerability_ver"; then
                if [ "$version" = "$vulnerability_ver" ]; then
                    echo -e "${RED}⚠️  [$source] $package_name@$version (vulnerable)${NC}"
                else
                    echo -e "${RED}⚠️  [$source] $package_name@$version (vulnerable - pre-release of $vulnerability_ver)${NC}"
                fi
                FOUND_VULNERABLE=1
                VULNERABLE_PACKAGES+=("$source|$package_name@$version")
                return 0
            fi
        done
    fi
    
    # Check version ranges
    if [ -n "$vulnerability_ranges" ]; then
        IFS='|' read -ra ranges_array <<< "$vulnerability_ranges"
        for range in "${ranges_array[@]}"; do
            [ -z "$range" ] && continue
            if version_in_range "$version" "$range"; then
                echo -e "${RED}⚠️  [$source] $package_name@$version (vulnerable - matches range: $range)${NC}"
                FOUND_VULNERABLE=1
                VULNERABLE_PACKAGES+=("$source|$package_name@$version")
                return 0
            fi
        done
    fi
    
    # Package is in the list but installed version is not vulnerable
    local vers_count=0
    local range_count=0
    if [ -n "$vulnerability_versions" ]; then
        # Count by counting pipe separators + 1
        local tmp="${vulnerability_versions//[^|]}"
        vers_count=$((${#tmp} + 1))
    fi
    if [ -n "$vulnerability_ranges" ]; then
        local tmp="${vulnerability_ranges//[^|]}"
        range_count=$((${#tmp} + 1))
    fi
    
    local info_parts=""
    if [ "$vers_count" -gt 0 ]; then
        info_parts="$vers_count version(s)"
    fi
    if [ "$range_count" -gt 0 ]; then
        if [ -n "$info_parts" ]; then
            info_parts="$info_parts + $range_count range(s)"
        else
            info_parts="$range_count range(s)"
        fi
    fi
    
    echo -e "${BLUE}ℹ️  [$source] $package_name@$version (OK - $info_parts known vulnerable)${NC}"
    return 1
}

# Function to analyze a package-lock.json file
# Optimized: uses awk for batch extraction instead of JSON parsing loops
# Uses POSIX-compatible awk syntax for macOS compatibility
analyze_package_lock() {
    local lockfile="$1"
    
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
        check_vulnerability "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"
}

# Function to analyze a yarn.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
# Supports both Yarn Classic (v1) and Yarn Berry (v2+) formats
analyze_yarn_lock() {
    local lockfile="$1"

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
        if (line != "") {
            print pkg "|" line
            pkg=""
        }
    }
    ' "$lockfile" 2>/dev/null | sort -u)
    
    # Process extracted packages
    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"
}

# Function to analyze a pnpm-lock.yaml file
# Optimized: unified awk extraction for both formats (POSIX-compatible)
analyze_pnpm_lock() {
    local lockfile="$1"
    
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
        check_vulnerability "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"
}

# Function to analyze a bun.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
analyze_bun_lock() {
    local lockfile="$1"
    
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
        check_vulnerability "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"
}

# Function to analyze a deno.lock file
# Optimized: uses awk for batch extraction (POSIX-compatible)
analyze_deno_lock() {
    local lockfile="$1"
    
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
        check_vulnerability "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"
}

# Main execution
main() {
    local use_default=true
    local use_config=true
    local custom_config=""
    local custom_sources=()
    local use_github=false
    
    # Parse command line arguments
    local current_csv_columns=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -s|--source)
                custom_sources+=("$2|")
                use_default=false
                use_config=false
                shift 2
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
            *)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    check_dependencies
    
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
    
    # Load data sources
    local sources_loaded=false
    
    # Try config file first
    if [ "$use_config" = true ]; then
        local config_to_use="${custom_config:-$CONFIG_FILE}"
        if load_config_file "$config_to_use"; then
            sources_loaded=true
        fi
    fi
    
    # Load custom sources from command line
    if [ ${#custom_sources[@]} -gt 0 ]; then
        for source in "${custom_sources[@]}"; do
            IFS='|' read -r url format columns <<< "$source"
            load_data_source "$url" "$format" "Custom Source" "$columns"
        done
        sources_loaded=true
    fi
    
    if [ "$sources_loaded" = false ]; then
        echo -e "${RED}❌ Error: No data sources configured${NC}"
        echo ""
        echo "Please provide data sources using one of these methods:"
        echo "  1. Create a .package-checker.config.json file"
        echo "  2. Use --source option to specify a vulnerability database URL"
        echo "  3. Use --config option to specify a custom configuration file"
        echo ""
        echo "Use --help for more information"
        exit 1
    fi
    
    # Count total packages - check lookup tables first (may be populated by CSV)
    local total_packages=0
    
    # First check if lookup tables have data (from CSV or JSON)
    local lookup_count=0
    if [ ${#VULN_EXACT_LOOKUP[@]} -gt 0 ] || [ ${#VULN_RANGE_LOOKUP[@]} -gt 0 ]; then
        # Count unique packages from lookup tables
        local all_pkgs=""
        for pkg in "${!VULN_EXACT_LOOKUP[@]}"; do
            all_pkgs+="$pkg"$'\n'
        done
        for pkg in "${!VULN_RANGE_LOOKUP[@]}"; do
            all_pkgs+="$pkg"$'\n'
        done
        lookup_count=$(echo "$all_pkgs" | sort -u | grep -c . || echo 0)
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
    
    # Determine search directory
    local search_dir="."
    if [ "$use_github" = true ] && [ -d "$GITHUB_OUTPUT_DIR" ]; then
        search_dir="$GITHUB_OUTPUT_DIR"
        echo -e "${BLUE}📂 Analyzing packages from GitHub: $search_dir${NC}"
        echo ""
    fi
    
    # Search for lockfiles
    echo "🔍 Searching for lockfiles and package.json files..."
    echo ""
    
    # Build ignore path arguments for find command from config
    local ignore_args=""
    for ignore_path in "${CONFIG_IGNORE_PATHS[@]}"; do
        ignore_args="$ignore_args ! -path \"*/$ignore_path/*\""
    done
    
    TEMP_LOCKFILES=$(eval "find \"$search_dir\" \( -name \"package-lock.json\" -o -name \"npm-shrinkwrap.json\" -o -name \"yarn.lock\" -o -name \"pnpm-lock.yaml\" -o -name \"bun.lock\" -o -name \"deno.lock\" \) -type f $ignore_args")
    
    # Filter using git check-ignore
    if git rev-parse --git-dir > /dev/null 2>&1; then
        LOCKFILES=""
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
    
    if [ -z "$LOCKFILES" ]; then
        echo "   ℹ️  No lockfiles found"
    else
        LOCKFILE_COUNT=$(echo "$LOCKFILES" | wc -l | tr -d ' ')
        echo "📦 Analyzing $LOCKFILE_COUNT lockfile(s)..."
        
        while IFS= read -r lockfile; do
            lockname=$(basename "$lockfile")
            
            case "$lockname" in
                "package-lock.json"|"npm-shrinkwrap.json")
                    analyze_package_lock "$lockfile"
                    ;;
                "yarn.lock")
                    analyze_yarn_lock "$lockfile"
                    ;;
                "pnpm-lock.yaml")
                    analyze_pnpm_lock "$lockfile"
                    ;;
                "bun.lock")
                    analyze_bun_lock "$lockfile"
                    ;;
                "deno.lock")
                    analyze_deno_lock "$lockfile"
                    ;;
            esac
        done <<< "$LOCKFILES"
    fi
    
    # Search for package.json files
    TEMP_FILES=$(eval "find \"$search_dir\" -name \"package.json\" -type f $ignore_args")
    
    if git rev-parse --git-dir > /dev/null 2>&1; then
        PACKAGE_JSON_FILES=""
        while IFS= read -r file; do
            if ! git check-ignore -q "$file" 2>/dev/null; then
                if [ -z "$PACKAGE_JSON_FILES" ]; then
                    PACKAGE_JSON_FILES="$file"
                else
                    PACKAGE_JSON_FILES="$PACKAGE_JSON_FILES
$file"
                fi
            fi
        done <<< "$TEMP_FILES"
    else
        PACKAGE_JSON_FILES="$TEMP_FILES"
    fi
    
    if [ -z "$PACKAGE_JSON_FILES" ]; then
        echo "   ℹ️  No package.json files found"
    else
        PACKAGE_COUNT=$(echo "$PACKAGE_JSON_FILES" | wc -l | tr -d ' ')
        echo "📦 Analyzing $PACKAGE_COUNT package.json file(s)..."
        
        # Build regex pattern of dependency types to match
        local dep_types_pattern=$(printf '%s|' "${CONFIG_DEPENDENCY_TYPES[@]}")
        dep_types_pattern="${dep_types_pattern%|}"  # Remove trailing |
        
        while IFS= read -r package_file; do
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
                # Use O(1) lookup instead of json_has_key
                if [ -n "${VULN_EXACT_LOOKUP[$pkg_name]+x}" ] || [ -n "${VULN_RANGE_LOOKUP[$pkg_name]+x}" ]; then
                    check_vulnerability "$pkg_name" "$version" "$package_file" || true
                fi
            done <<< "$deps"
        done <<< "$PACKAGE_JSON_FILES"
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}📊 SUMMARY${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ $FOUND_VULNERABLE -eq 0 ]; then
        echo -e "${GREEN}✅ No vulnerable packages detected${NC}"
    else
        # Count unique vulnerable packages
        local unique_vulns=$(printf '%s\n' "${VULNERABLE_PACKAGES[@]}" | cut -d'|' -f2 | sort -u | wc -l | tr -d ' ')
        local total_occurrences=${#VULNERABLE_PACKAGES[@]}
        
        echo -e "${RED}⚠️  Found ${unique_vulns} vulnerable package(s) in ${total_occurrences} location(s)${NC}"
        echo ""
        
        # Group by package
        declare -A pkg_files
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file pkg <<< "$vuln"
            if [ -z "${pkg_files[$pkg]}" ]; then
                pkg_files[$pkg]="$file"
            else
                pkg_files[$pkg]="${pkg_files[$pkg]}|$file"
            fi
        done
        
        # Display grouped results
        for pkg in $(printf '%s\n' "${!pkg_files[@]}" | sort -u); do
            echo -e "${RED}   ⚠️  $pkg${NC}"
            IFS='|' read -ra files <<< "${pkg_files[$pkg]}"
            for file in "${files[@]}"; do
                echo -e "${YELLOW}      └─ $file${NC}"
            done
        done
        
        echo ""
        echo -e "${YELLOW}💡 Recommendations:${NC}"
        echo "   • Update vulnerable packages to patched versions"
        echo "   • Run your package manager's audit command for more details"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    exit $FOUND_VULNERABLE
}

# Run main function
main "$@"