#!/usr/bin/env bash

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

set -e

# Default configuration
CONFIG_FILE=".pkgcheck.json"

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
    echo "$json" | grep -oE '"[^"]+"\s*:' | sed 's/"\([^"]*\)"\s*:/\1/' | sort -u
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
# Usage: json_object_length "$json"
json_object_length() {
    local json="$1"
    json_keys "$json" | wc -l | tr -d ' '
}

# Merge two JSON objects (simple merge, second overwrites first)
# Usage: json_merge "$json1" "$json2"
json_merge() {
    local json1="$1"
    local json2="$2"
    
    # Extract content without outer braces
    local content1=$(echo "$json1" | sed 's/^[[:space:]]*{//;s/}[[:space:]]*$//')
    local content2=$(echo "$json2" | sed 's/^[[:space:]]*{//;s/}[[:space:]]*$//')
    
    # Trim whitespace
    content1=$(echo "$content1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    content2=$(echo "$content2" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if [ -z "$content1" ]; then
        echo "{$content2}"
    elif [ -z "$content2" ]; then
        echo "{$content1}"
    else
        echo "{$content1,$content2}"
    fi
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
    -c, --config FILE       Path to configuration file (default: .pkgcheck.json)
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

CONFIGURATION FILE FORMAT (.pkgcheck.json):
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
  ]
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

# Make a GitHub API request
github_request() {
    local url="$1"
    local response
    local http_code
    
    local auth_header=""
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="-H \"Authorization: Bearer $GITHUB_TOKEN\""
    fi
    
    response=$(curl -sS -w "\n%{http_code}" \
        ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        -H "Accept: application/vnd.github.v3+json" \
        -H "User-Agent: package-checker-script" \
        "$url")
    
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')
    
    if [ "$http_code" != "200" ]; then
        echo -e "${RED}❌ GitHub API error ($http_code): $response${NC}" >&2
        return 1
    fi
    
    echo "$response"
}

# Get all repositories from a GitHub organization
get_github_repositories() {
    echo -e "${BLUE}🔍 Fetching repositories for organization: $GITHUB_ORG${NC}"
    
    local all_repos="[]"
    local page=1
    local per_page=100
    
    while true; do
        local url="https://api.github.com/orgs/${GITHUB_ORG}/repos?page=${page}&per_page=${per_page}"
        local repos
        
        repos=$(github_request "$url") || return 1
        
        local count=$(json_array_length "$repos")
        
        if [ "$count" -eq 0 ]; then
            break
        fi
        
        # Merge arrays
        if [ "$all_repos" = "[]" ]; then
            all_repos="$repos"
        else
            # Simple array concatenation
            local content1=$(echo "$all_repos" | sed 's/^[[:space:]]*\[//;s/\][[:space:]]*$//')
            local content2=$(echo "$repos" | sed 's/^[[:space:]]*\[//;s/\][[:space:]]*$//')
            all_repos="[$content1,$content2]"
        fi
        echo "   Found $count repositories on page $page"
        
        if [ "$count" -lt "$per_page" ]; then
            break
        fi
        
        page=$((page + 1))
        sleep "$GITHUB_RATE_LIMIT_DELAY"
    done
    
    local total=$(json_array_length "$all_repos")
    echo -e "${GREEN}✅ Total repositories found: $total${NC}"
    echo ""
    
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
    
    # Find all package.json and lockfiles (excluding node_modules)
    # Extract tree array and filter paths
    local tree_array=$(json_get_array "$tree_response" "tree")
    local target_files=""
    local len=$(json_array_length "$tree_array")
    local i=0
    
    while [ $i -lt $len ]; do
        local item=$(json_array_get "$tree_array" $i)
        local path=$(json_get_value "$item" "path")
        
        # Check if path matches our targets and doesn't contain node_modules
        if [[ ! "$path" =~ node_modules ]]; then
            case "$path" in
                *package.json|*package-lock.json|*npm-shrinkwrap.json|*yarn.lock|*pnpm-lock.yaml|*bun.lock|*deno.lock)
                    if [ -z "$target_files" ]; then
                        target_files="$path"
                    else
                        target_files="$target_files"$'\n'"$path"
                    fi
                    ;;
            esac
        fi
        i=$((i + 1))
    done
    
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
        
        # Extract items from search results
        local items_array=$(json_get_array "$search_results" "items")
        local items_len=$(json_array_length "$items_array")
        local j=0
        
        while [ $j -lt $items_len ]; do
            local item=$(json_array_get "$items_array" $j)
            local path=$(json_get_value "$item" "path")
            local url=$(json_get_value "$item" "url")
            if [ -n "$path" ] && [ -n "$url" ]; then
                local file_entry="$path|$url"
                if [ -z "$all_files" ]; then
                    all_files="$file_entry"
                else
                    all_files="$all_files"$'\n'"$file_entry"
                fi
            fi
            j=$((j + 1))
        done
        
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
        # Organization mode - requires token for Search API
        local repos
        repos=$(get_github_repositories) || return 1
        
        local repo_count=$(json_array_length "$repos")
        
        for i in $(seq 0 $((repo_count - 1))); do
            local repo=$(json_array_get "$repos" $i)
            local repo_name=$(json_get_value "$repo" "name")
            local repo_full_name=$(json_get_value "$repo" "full_name")
            
            echo -e "${BLUE}Processing: $repo_name${NC}"
            
            search_package_json_in_repo "$repo_full_name" "$repo_name"
            
            sleep "$GITHUB_RATE_LIMIT_DELAY"
        done
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ GitHub packages fetched to: $(realpath "$GITHUB_OUTPUT_DIR")${NC}"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# Normalize CSV data by joining multi-line quoted values into single lines
# Also removes Windows-style carriage returns
normalize_csv_multiline() {
    local csv_data="$1"
    
    # First, remove Windows-style carriage returns (^M / \r)
    csv_data=$(echo "$csv_data" | tr -d '\r')
    
    local result=""
    local in_quotes=false
    local current_line=""
    
    while IFS= read -r line || [ -n "$line" ]; do
        # Count quotes in this line
        local quote_count=0
        local temp_line="$line"
        while [[ "$temp_line" == *\"* ]]; do
            quote_count=$((quote_count + 1))
            temp_line="${temp_line#*\"}"
        done
        
        if [ "$in_quotes" = true ]; then
            # Continue accumulating the multi-line value
            current_line="${current_line} ${line}"
            # Check if quotes are now balanced (odd number closes the quote)
            if [ $((quote_count % 2)) -eq 1 ]; then
                in_quotes=false
                result="${result}${current_line}"$'\n'
                current_line=""
            fi
        else
            # Start of a new line
            if [ $((quote_count % 2)) -eq 1 ]; then
                # Odd number of quotes means we're starting a multi-line value
                in_quotes=true
                current_line="$line"
            else
                # Even number of quotes (including 0), this is a complete line
                result="${result}${line}"$'\n'
            fi
        fi
    done <<< "$csv_data"
    
    # Handle any remaining content
    if [ -n "$current_line" ]; then
        result="${result}${current_line}"$'\n'
    fi
    
    echo "$result"
}

# Parse CSV data into JSON format
# Supports custom column specification and version ranges
parse_csv_to_json() {
    local csv_data="$1"
    
    # First, normalize multi-line quoted values
    csv_data=$(normalize_csv_multiline "$csv_data")
    
    # If no custom columns specified, use the default format
    if [ ${#CSV_COLUMNS[@]} -eq 0 ]; then
        parse_csv_default "$csv_data"
        return
    fi
    
    local header_line=true
    local package_col_idx=-1
    local version_col_idx=-1
    
    # Use associative arrays to collect versions and ranges per package
    declare -A pkg_versions
    declare -A pkg_ranges
    declare -a pkg_order
    
    # Build column index mapping from first line (header)
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue
        
        if [ "$header_line" = true ]; then
            # Parse header to get column indices
            local parsed=$(parse_csv_line "$line")
            local field_index=1
            
            IFS='|' read -ra fields <<< "$parsed"
            for field in "${fields[@]}"; do
                local clean_field=$(echo "$field" | tr '[:upper:]' '[:lower:]')
                # Check if this field matches our target columns
                for col in "${CSV_COLUMNS[@]}"; do
                    local clean_col=$(echo "$col" | xargs | tr '[:upper:]' '[:lower:]')
                    if [ "$clean_field" = "$clean_col" ]; then
                        if [ $package_col_idx -eq -1 ]; then
                            package_col_idx=$field_index
                        elif [ $version_col_idx -eq -1 ]; then
                            version_col_idx=$field_index
                        fi
                    fi
                done
                field_index=$((field_index + 1))
            done
            
            # If no matches found by name, use position
            if [ $package_col_idx -eq -1 ]; then
                package_col_idx=1
            fi
            if [ $version_col_idx -eq -1 ]; then
                version_col_idx=2
            fi
            
            header_line=false
            continue
        fi
        
        # Parse the CSV line properly handling quoted fields
        local parsed=$(parse_csv_line "$line")
        IFS='|' read -ra fields <<< "$parsed"
        
        # Skip empty lines
        [ ${#fields[@]} -eq 0 ] && continue
        
        # Extract package and version based on column indices
        local package=""
        local version=""
        
        if [ $package_col_idx -gt 0 ] && [ $package_col_idx -le ${#fields[@]} ]; then
            package="${fields[$((package_col_idx - 1))]}"
        fi
        
        if [ $version_col_idx -gt 0 ] && [ $version_col_idx -le ${#fields[@]} ]; then
            version="${fields[$((version_col_idx - 1))]}"
        fi
        
        # Skip if no valid package or version
        [ -z "$package" ] || [ -z "$version" ] && continue
        
        # Track package order for consistent output
        if [ -z "${pkg_versions[$package]+x}" ] && [ -z "${pkg_ranges[$package]+x}" ]; then
            pkg_order+=("$package")
        fi
        
        # Determine if it's a range or exact version
        if is_version_range "$version"; then
            # It's a range - add to vulnerability_range
            if [ -z "${pkg_ranges[$package]}" ]; then
                pkg_ranges[$package]="\"$version\""
            else
                pkg_ranges[$package]="${pkg_ranges[$package]},\"$version\""
            fi
        else
            # It's an exact version - add to vulnerability_version
            if [ -z "${pkg_versions[$package]}" ]; then
                pkg_versions[$package]="\"$version\""
            else
                pkg_versions[$package]="${pkg_versions[$package]},\"$version\""
            fi
        fi
        
    done <<< "$csv_data"
    
    # Build JSON output
    local json_output="{"
    local first_package=true
    
    for package in "${pkg_order[@]}"; do
        if [ "$first_package" = false ]; then
            json_output="${json_output},"
        fi
        first_package=false
        
        json_output="${json_output}\"$package\":{"
        local has_content=false
        
        # Add vulnerability_version if we have exact versions
        if [ -n "${pkg_versions[$package]}" ]; then
            json_output="${json_output}\"vulnerability_version\":[${pkg_versions[$package]}]"
            has_content=true
        fi
        
        # Add vulnerability_range if we have ranges
        if [ -n "${pkg_ranges[$package]}" ]; then
            if [ "$has_content" = true ]; then
                json_output="${json_output},"
            fi
            json_output="${json_output}\"vulnerability_range\":[${pkg_ranges[$package]}]"
        fi
        
        json_output="${json_output}}"
    done
    
    json_output="${json_output}}"
    echo "$json_output"
}

# Check if a version string is a range (contains operators like >=, <=, >, <)
is_version_range() {
    local version="$1"
    if [[ "$version" =~ (>=|<=|>|<) ]]; then
        return 0  # true - it's a range
    fi
    return 1  # false - it's an exact version
}

# Parse a CSV line handling quoted fields correctly
# Returns: field1|field2|field3|...
parse_csv_line() {
    local line="$1"
    local result=""
    local in_quotes=false
    local current_field=""
    local i=0
    local len=${#line}
    
    while [ $i -lt $len ]; do
        local char="${line:$i:1}"
        
        if [ "$char" = '"' ]; then
            in_quotes=$([ "$in_quotes" = true ] && echo false || echo true)
        elif [ "$char" = ',' ] && [ "$in_quotes" = false ]; then
            # Field separator - add field to result
            if [ -n "$result" ]; then
                result="${result}|"
            fi
            # Remove surrounding quotes and trim
            current_field=$(echo "$current_field" | sed 's/^"//;s/"$//' | xargs)
            result="${result}${current_field}"
            current_field=""
        else
            current_field="${current_field}${char}"
        fi
        
        i=$((i + 1))
    done
    
    # Add last field
    if [ -n "$result" ]; then
        result="${result}|"
    fi
    current_field=$(echo "$current_field" | sed 's/^"//;s/"$//' | xargs)
    result="${result}${current_field}"
    
    echo "$result"
}

# Parse CSV data using the default format (for backward compatibility)
# Now supports version ranges and 3-column format (package,version,source)
parse_csv_default() {
    local csv_data="$1"
    
    # Normalize multi-line quoted values if not already done
    csv_data=$(normalize_csv_multiline "$csv_data")
    
    # Use associative arrays to collect versions and ranges per package
    declare -A pkg_versions
    declare -A pkg_ranges
    declare -a pkg_order
    
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue
        
        # Parse the CSV line properly handling quoted fields
        local parsed=$(parse_csv_line "$line")
        
        # Extract package and version (first two fields)
        local package=$(echo "$parsed" | cut -d'|' -f1)
        local version=$(echo "$parsed" | cut -d'|' -f2)
        
        # Skip headers
        [[ "$package" == "package" || "$package" == "package_name" ]] && continue
        
        # Skip if no valid package or version
        [ -z "$package" ] || [ -z "$version" ] && continue
        
        # Track package order for consistent output
        if [ -z "${pkg_versions[$package]+x}" ] && [ -z "${pkg_ranges[$package]+x}" ]; then
            pkg_order+=("$package")
        fi
        
        # Determine if it's a range or exact version
        if is_version_range "$version"; then
            # It's a range - add to vulnerability_range
            if [ -z "${pkg_ranges[$package]}" ]; then
                pkg_ranges[$package]="\"$version\""
            else
                pkg_ranges[$package]="${pkg_ranges[$package]},\"$version\""
            fi
        else
            # It's an exact version - add to vulnerability_version
            if [ -z "${pkg_versions[$package]}" ]; then
                pkg_versions[$package]="\"$version\""
            else
                pkg_versions[$package]="${pkg_versions[$package]},\"$version\""
            fi
        fi
    done <<< "$csv_data"
    
    # Build JSON output
    local json_output="{"
    local first_package=true
    
    for package in "${pkg_order[@]}"; do
        if [ "$first_package" = false ]; then
            json_output="${json_output},"
        fi
        first_package=false
        
        json_output="${json_output}\"$package\":{"
        local has_content=false
        
        # Add vulnerability_version if we have exact versions
        if [ -n "${pkg_versions[$package]}" ]; then
            json_output="${json_output}\"vulnerability_version\":[${pkg_versions[$package]}]"
            has_content=true
        fi
        
        # Add vulnerability_range if we have ranges
        if [ -n "${pkg_ranges[$package]}" ]; then
            if [ "$has_content" = true ]; then
                json_output="${json_output},"
            fi
            json_output="${json_output}\"vulnerability_range\":[${pkg_ranges[$package]}]"
        fi
        
        json_output="${json_output}}"
    done
    
    json_output="${json_output}}"
    echo "$json_output"
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
    case "$format" in
        json)
            parsed_data="$raw_data"
            ;;
        csv)
            parsed_data=$(parse_csv_to_json "$raw_data")
            ;;
        *)
            echo -e "${RED}❌ Error: Unsupported format '$format'${NC}"
            return 1
            ;;
    esac
    
    # Merge into global vulnerability data
    if [ -z "$VULN_DATA" ]; then
        VULN_DATA="$parsed_data"
    else
        # Merge JSON objects
        VULN_DATA=$(json_merge "$VULN_DATA" "$parsed_data")
    fi
    
    local pkg_count=$(json_object_length "$parsed_data")
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
    
    # Parse config file and extract sources array
    local sources_array=$(json_get_array "$config_content" "sources")
    local sources_count=$(json_array_length "$sources_array")
    
    if [ "$sources_count" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Warning: No sources found in configuration file${NC}"
        return 1
    fi
    
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

# Function to check if a package+version is vulnerable
check_vulnerability() {
    local package_name="$1"
    local version="$2"
    local source="$3"
    
    # Check if package exists in vulnerability database
    if ! json_has_key "$VULN_DATA" "$package_name"; then
        return 1
    fi
    
    # Get package data
    local pkg_data=$(json_get_object "$VULN_DATA" "$package_name")
    
    # Get vulnerable versions for this package
    local vulnerability_vers_array=$(json_get_array "$pkg_data" "vulnerability_version")
    local vulnerability_versions=""
    if [ "$vulnerability_vers_array" != "[]" ] && [ "$vulnerability_vers_array" != "{}" ] && [ -n "$vulnerability_vers_array" ]; then
        vulnerability_versions=$(json_array_iterate "$vulnerability_vers_array")
    fi
    
    # Get vulnerable ranges for this package
    local vulnerability_range_array=$(json_get_array "$pkg_data" "vulnerability_range")
    local vulnerability_ranges=""
    if [ "$vulnerability_range_array" != "[]" ] && [ "$vulnerability_range_array" != "{}" ] && [ -n "$vulnerability_range_array" ]; then
        vulnerability_ranges=$(json_array_iterate "$vulnerability_range_array")
    fi
    
    # Check exact version matches
    if [ -n "$vulnerability_versions" ]; then
        while IFS= read -r vulnerability_ver; do
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
        done <<< "$vulnerability_versions"
    fi
    
    # Check version ranges
    if [ -n "$vulnerability_ranges" ]; then
        while IFS= read -r range; do
            [ -z "$range" ] && continue
            if version_in_range "$version" "$range"; then
                echo -e "${RED}⚠️  [$source] $package_name@$version (vulnerable - matches range: $range)${NC}"
                FOUND_VULNERABLE=1
                VULNERABLE_PACKAGES+=("$source|$package_name@$version")
                return 0
            fi
        done <<< "$vulnerability_ranges"
    fi
    
    # Package is in the list but installed version is not vulnerable
    local vers_count=0
    local range_count=0
    if [ -n "$vulnerability_versions" ]; then
        vers_count=$(echo "$vulnerability_versions" | grep -c . 2>/dev/null | tr -d '[:space:]' || echo "0")
    fi
    if [ -n "$vulnerability_ranges" ]; then
        range_count=$(echo "$vulnerability_ranges" | grep -c . 2>/dev/null | tr -d '[:space:]' || echo "0")
    fi
    
    local info_parts=""
    if [ "$vers_count" -gt 0 ] 2>/dev/null; then
        info_parts="$vers_count version(s)"
    fi
    if [ "$range_count" -gt 0 ] 2>/dev/null; then
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
analyze_package_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    local content=$(cat "$lockfile")
    
    # Parse dependencies (npm v1 format)
    local deps_obj=$(json_get_object "$content" "dependencies")
    if [ -n "$deps_obj" ] && [ "$deps_obj" != "{}" ]; then
        local dep_keys=$(json_keys "$deps_obj")
        while IFS= read -r key; do
            [ -z "$key" ] && continue
            local dep_data=$(json_get_object "$deps_obj" "$key")
            local version=$(json_get_value "$dep_data" "version")
            if [ -n "$version" ] && [ "$version" != "null" ]; then
                check_vulnerability "$key" "$version" "$lockfile" || true
            fi
        done <<< "$dep_keys"
    fi
    
    # Parse packages (npm v2/v3 format) - extract from node_modules/ entries
    local packages_obj=$(json_get_object "$content" "packages")
    if [ -n "$packages_obj" ] && [ "$packages_obj" != "{}" ]; then
        # Use grep to find all node_modules entries with versions
        local nm_entries=$(echo "$packages_obj" | grep -oE '"node_modules/[^"]+"\s*:\s*\{[^}]*"version"\s*:\s*"[^"]*"' || true)
        while IFS= read -r entry; do
            [ -z "$entry" ] && continue
            # Extract package name (last part after node_modules/)
            local pkg_path=$(echo "$entry" | grep -oE 'node_modules/[^"]+' | head -1)
            local pkg_name="${pkg_path##node_modules/}"
            # Handle scoped packages - get full name after last node_modules/
            if [[ "$pkg_name" == *"node_modules/"* ]]; then
                pkg_name="${pkg_name##*node_modules/}"
            fi
            local version=$(echo "$entry" | grep -oE '"version"\s*:\s*"[^"]*"' | sed 's/"version"[[:space:]]*:[[:space:]]*"//;s/"$//')
            if [ -n "$pkg_name" ] && [ -n "$version" ]; then
                check_vulnerability "$pkg_name" "$version" "$lockfile" || true
            fi
        done <<< "$nm_entries"
    fi
}

# Function to analyze a yarn.lock file
analyze_yarn_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    current_package=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^[^\s].*:$ ]] && [[ ! "$line" =~ ^[[:space:]] ]]; then
            pkg_line=$(echo "$line" | sed 's/:$//' | tr -d '"')
            if [[ "$pkg_line" =~ ^(@[^@]+)@.*$ ]]; then
                current_package="${BASH_REMATCH[1]}"
            elif [[ "$pkg_line" =~ ^([^@]+)@.*$ ]]; then
                current_package="${BASH_REMATCH[1]}"
            fi
        elif [[ "$line" =~ ^[[:space:]]+version[[:space:]]+\"?([^\"]+)\"?$ ]] && [ -n "$current_package" ]; then
            pkg_version="${BASH_REMATCH[1]}"
            check_vulnerability "$current_package" "$pkg_version" "$lockfile" || true
            current_package=""
        fi
    done < "$lockfile"
}

# Function to analyze a pnpm-lock.yaml file
analyze_pnpm_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    # Detect lockfile version to use appropriate parsing
    local lockfile_version=$(grep -m1 "^lockfileVersion:" "$lockfile" | sed "s/lockfileVersion:[[:space:]]*['\"]*//" | sed "s/['\"]//g" | tr -d ' ')
    
    if command -v yq &> /dev/null; then
        # yq is available - use it for more reliable parsing
        PACKAGES=$(yq eval '.packages | keys | .[]' "$lockfile" 2>/dev/null | sed 's|^/||' | sed "s/'//g")
    else
        # Fallback to grep-based parsing
        # Check if it's the new format (lockfileVersion 6.0+, 9.0, etc.) or old format (5.x with /)
        local old_format_packages=$(grep -E "^\s+/" "$lockfile" 2>/dev/null | sed 's/^[[:space:]]*//' | sed 's/:$//' | sed 's|^/||')
        
        if [ -n "$old_format_packages" ]; then
            # Old format (pnpm lockfile v5.x): packages start with /
            PACKAGES="$old_format_packages"
        else
            # New format (pnpm lockfile v6.0+, v9.0): packages are listed as 'package@version': or package@version:
            # Match lines like:  'next@15.0.3': or  next@15.0.3: in the packages section
            PACKAGES=$(awk '
                /^packages:/ { in_packages=1; next }
                /^[a-zA-Z]/ && !/^[[:space:]]/ { in_packages=0 }
                in_packages && /^[[:space:]]+'\''?@?[a-zA-Z0-9]/ {
                    line = $0
                    # Remove leading whitespace
                    gsub(/^[[:space:]]+/, "", line)
                    # Remove trailing colon
                    gsub(/:$/, "", line)
                    # Remove surrounding quotes
                    gsub(/^'\''/, "", line)
                    gsub(/'\''$/, "", line)
                    # Only print if it contains @ (package@version format) and not peer deps resolution like (...)
                    if (line ~ /@[0-9]/ && line !~ /\(/) {
                        print line
                    }
                }
            ' "$lockfile" 2>/dev/null)
        fi
    fi
    
    if [ -n "$PACKAGES" ]; then
        while IFS= read -r pkg_line; do
            if [[ "$pkg_line" =~ ^(@?[^@]+)@(.+)$ ]]; then
                pkg_name="${BASH_REMATCH[1]}"
                pkg_version="${BASH_REMATCH[2]}"
                check_vulnerability "$pkg_name" "$pkg_version" "$lockfile" || true
            fi
        done <<< "$PACKAGES"
    fi
}

# Function to analyze a bun.lock file
analyze_bun_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    # bun.lock format: "package-name": ["package-name@version", ...]
    # Extract the first element of each array in packages section which contains name@version
    PACKAGES=$(grep -E '^\s+"[^"]+": \["[^"]+@[^"]+",?\s*$' "$lockfile" | \
               sed -E 's/.*\["([^"]+@[^"]+)".*/\1/' | \
               sort -u)
    
    # Also check workspaces dependencies for direct versions
    local workspace_deps=$(grep -A 100 '"workspaces"' "$lockfile" | grep -E '^\s+"[^"]+": "[0-9]' | \
                          sed -E 's/.*"([^"]+)": "([^"]+)".*/\1@\2/')
    
    if [ -n "$workspace_deps" ]; then
        PACKAGES="$PACKAGES"$'\n'"$workspace_deps"
    fi
    
    if [ -n "$PACKAGES" ]; then
        while IFS= read -r pkg_line; do
            [ -z "$pkg_line" ] && continue
            if [[ "$pkg_line" =~ ^(.+)@([0-9].*)$ ]]; then
                pkg_name="${BASH_REMATCH[1]}"
                pkg_version="${BASH_REMATCH[2]}"
                check_vulnerability "$pkg_name" "$pkg_version" "$lockfile" || true
            fi
        done <<< "$PACKAGES"
    fi
}

# Function to analyze a deno.lock file
analyze_deno_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    local content=$(cat "$lockfile")
    
    # Deno.lock v5 format: .npm contains packages as "package@version_peer_deps" keys
    # We need to extract just "package@version" (before any underscore)
    local npm_obj=$(json_get_object "$content" "npm")
    
    if [ -n "$npm_obj" ] && [ "$npm_obj" != "{}" ]; then
        # Extract all keys from npm object
        local npm_keys=$(json_keys "$npm_obj")
        
        while IFS= read -r key; do
            [ -z "$key" ] && continue
            # Split by underscore to get package@version (before peer deps suffix)
            local pkg_at_version="${key%%_*}"
            # Extract package name and version
            if [[ "$pkg_at_version" =~ ^(@?[^@]+)@([^_]+)$ ]]; then
                local pkg_name="${BASH_REMATCH[1]}"
                local pkg_version="${BASH_REMATCH[2]}"
                check_vulnerability "$pkg_name" "$pkg_version" "$lockfile" || true
            fi
        done <<< "$npm_keys"
    fi
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
        echo "  1. Create a .pkgcheck.json file"
        echo "  2. Use --source option to specify a vulnerability database URL"
        echo "  3. Use --config option to specify a custom configuration file"
        echo ""
        echo "Use --help for more information"
        exit 1
    fi
    
    local total_packages=$(json_object_length "$VULN_DATA")
    echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages${NC}"
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
    
    TEMP_LOCKFILES=$(find "$search_dir" \( -name "package-lock.json" -o -name "npm-shrinkwrap.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" -o -name "deno.lock" \) -type f ! -path "*/node_modules/*" ! -path "*/.yarn/*" ! -path "*/.git/*")
    
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
    TEMP_FILES=$(find "$search_dir" -name "package.json" -type f ! -path "*/node_modules/*" ! -path "*/.yarn/*" ! -path "*/.git/*")
    
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
        
        while IFS= read -r package_file; do
            local pkg_content=$(cat "$package_file")
            
            # Extract dependencies from all dependency types
            local dep_types=("dependencies" "devDependencies" "optionalDependencies" "peerDependencies")
            
            for dep_type in "${dep_types[@]}"; do
                local deps_obj=$(json_get_object "$pkg_content" "$dep_type")
                if [ -n "$deps_obj" ] && [ "$deps_obj" != "{}" ]; then
                    local dep_keys=$(json_keys "$deps_obj")
                    while IFS= read -r pkg_name; do
                        [ -z "$pkg_name" ] && continue
                        
                        # Check if package is in vulnerability database
                        if json_has_key "$VULN_DATA" "$pkg_name"; then
                            local pkg_version_spec=$(json_get_value "$deps_obj" "$pkg_name")
                            # Extract exact version from version spec (remove ^, ~, >=, etc.)
                            local exact_version=$(echo "$pkg_version_spec" | sed -E 's/^[\^~>=<]+//' | sed -E 's/\s.*//')
                            
                            # Check if this exact version is vulnerable
                            check_vulnerability "$pkg_name" "$exact_version" "$package_file" || true
                        fi
                    done <<< "$dep_keys"
                fi
            done
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