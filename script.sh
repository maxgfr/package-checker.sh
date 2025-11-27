#!/bin/bash

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

set -e

# Default configuration
CONFIG_FILE=".package-checker-config.json"

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

# Help message
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

A tool to check Node.js projects for vulnerable packages against custom data sources.

OPTIONS:
    -h, --help              Show this help message
    -u, --url URL           Data source URL (can be used multiple times)
    -f, --format FORMAT     Data format: json or csv (default: json)
    -c, --config FILE       Path to configuration file (default: .package-checker-config.json)
    --no-config             Skip loading configuration file
    --csv-columns COLS      CSV columns specification (e.g., "1,2" or "package_name,package_versions")
    
EXAMPLES:
    # Use configuration file
    $0
    
    # Use custom JSON source
    $0 --url https://example.com/vulns.json --format json
    
    # Use custom CSV source
    $0 --url https://example.com/vulns.csv --format csv
    
    # Use CSV with specific columns (package_name=1, package_versions=2)
    $0 --url data.csv --format csv --csv-columns "1,2"
    
    # Use CSV with column names
    $0 --url data.csv --format csv --csv-columns "package_name,package_versions"
    
    # Use multiple sources
    $0 --url https://example.com/vulns1.json --url https://example.com/vulns2.csv
    
    # Use configuration file
    $0 --config my-config.json

CONFIGURATION FILE FORMAT (.package-checker-config.json):
{
  "sources": [
    {
      "url": "https://example.com/vulns.json",
      "format": "json",
      "name": "My Vulnerability List"
    },
    {
      "url": "https://example.com/vulns.csv",
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
    "vuln_vers": ["1.0.0", "2.0.0"]
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

# Check that jq is installed
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        echo "❌ Error: 'jq' must be installed to run this script"
        echo "   Installation: brew install jq (macOS) or apt-get install jq (Linux)"
        exit 1
    fi
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
parse_csv_to_json() {
    local csv_data="$1"
    
    # First, normalize multi-line quoted values
    csv_data=$(normalize_csv_multiline "$csv_data")
    
    # If no custom columns specified, use the default format
    if [ ${#CSV_COLUMNS[@]} -eq 0 ]; then
        parse_csv_default "$csv_data"
        return
    fi
    
    local json_output="{"
    local current_package=""
    local first_package=true
    local header_line=true
    local package_col_idx=-1
    local version_col_idx=-1
    
    # Build column index mapping from first line (header)
    while IFS= read -r line; do
        if [ "$header_line" = true ]; then
            # Parse header to get column indices - use a simple approach
            local field_index=1
            IFS=',' read -ra fields <<< "$line"
            for field in "${fields[@]}"; do
                local clean_field=$(echo "$field" | xargs | tr '[:upper:]' '[:lower:]')
                # Check if this field matches our target columns
                for col in "${CSV_COLUMNS[@]}"; do
                    local clean_col=$(echo "$col" | xargs)
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
        
        IFS=',' read -ra fields <<< "$line"
        
        # Skip empty lines
        [ ${#fields[@]} -eq 0 ] && continue
        [ ${#fields[@]} -eq 1 ] && [ -z "${fields[0]}" ] && continue
        
        # Extract package and version based on column indices
        local package=""
        local version=""
        
        if [ $package_col_idx -gt 0 ] && [ $package_col_idx -le ${#fields[@]} ]; then
            package=$(echo "${fields[$((package_col_idx - 1))]}" | xargs)
        fi
        
        if [ $version_col_idx -gt 0 ] && [ $version_col_idx -le ${#fields[@]} ]; then
            version=$(echo "${fields[$((version_col_idx - 1))]}" | xargs)
        fi
        
        # Skip if no valid package or version
        [ -z "$package" ] || [ -z "$version" ] && continue
        
        if [ "$package" != "$current_package" ]; then
            # Close previous package if exists
            if [ -n "$current_package" ]; then
                json_output="${json_output}]}"
                first_package=false
            fi
            
            # Start new package
            if [ "$first_package" = false ]; then
                json_output="${json_output},"
            fi
            json_output="${json_output}\"$package\":{\"vuln_vers\":["
            current_package="$package"
            first_version=true
        else
            first_version=false
        fi
        
        # Add version
        if [ "$first_version" = false ]; then
            json_output="${json_output},"
        fi
        json_output="${json_output}\"$version\""
        
    done <<< "$csv_data"
    
    # Close last package if exists
    if [ -n "$current_package" ]; then
        json_output="${json_output}]}"
    fi
    
    json_output="${json_output}}"
    echo "$json_output"
}

# Parse CSV data using the default format (for backward compatibility)
parse_csv_default() {
    local csv_data="$1"
    
    # Normalize multi-line quoted values if not already done
    csv_data=$(normalize_csv_multiline "$csv_data")
    
    local json_output="{"
    local current_package=""
    local first_package=true
    
    while IFS=',' read -r package version; do
        # Skip empty lines and headers
        [[ -z "$package" || "$package" == "package" ]] && continue
        
        # Trim whitespace
        package=$(echo "$package" | xargs)
        version=$(echo "$version" | xargs)
        
        if [ "$package" != "$current_package" ]; then
            # Close previous package if exists
            if [ -n "$current_package" ]; then
                json_output="${json_output}]}"
                first_package=false
            fi
            
            # Start new package
            if [ "$first_package" = false ]; then
                json_output="${json_output},"
            fi
            json_output="${json_output}\"$package\":{\"vuln_vers\":["
            current_package="$package"
            first_version=true
        else
            first_version=false
        fi
        
        # Add version
        if [ "$first_version" = false ]; then
            json_output="${json_output},"
        fi
        json_output="${json_output}\"$version\""
    done <<< "$csv_data"
    
    # Close last package if exists
    if [ -n "$current_package" ]; then
        json_output="${json_output}]}"
    fi
    
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
        # Merge JSON objects using jq
        VULN_DATA=$(jq -s '.[0] * .[1]' <(echo "$VULN_DATA") <(echo "$parsed_data"))
    fi
    
    local pkg_count=$(echo "$parsed_data" | jq 'length')
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
    
    # Parse config file and extract sources
    local sources_count=$(jq '.sources | length' "$config_path" 2>/dev/null || echo "0")
    
    if [ "$sources_count" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Warning: No sources found in configuration file${NC}"
        return 1
    fi
    
    for i in $(seq 0 $((sources_count - 1))); do
        local url=$(jq -r ".sources[$i].url" "$config_path")
        local format=$(jq -r ".sources[$i].format // \"\"" "$config_path")
        local name=$(jq -r ".sources[$i].name // \"Source $((i+1))\"" "$config_path")
        local columns=$(jq -r ".sources[$i].columns // \"\"" "$config_path")
        
        # Pass format only if explicitly specified
        if [ -n "$format" ]; then
            load_data_source "$url" "$format" "$name" "$columns"
        else
            load_data_source "$url" "" "$name" "$columns"
        fi
    done
    
    return 0
}

# Function to check if a package+version is vulnerable
check_vulnerability() {
    local package_name="$1"
    local version="$2"
    local source="$3"
    
    # Get vulnerable versions for this package
    local vuln_versions=$(echo "$VULN_DATA" | jq -r --arg pkg "$package_name" '.[$pkg].vuln_vers // [] | .[]')
    
    if [ -z "$vuln_versions" ]; then
        return 1
    fi
    
    # Check if installed version matches a vulnerable version
    while IFS= read -r vuln_ver; do
        if [ "$version" = "$vuln_ver" ]; then
            echo -e "${RED}⚠️  [$source] $package_name@$version (vulnerable)${NC}"
            FOUND_VULNERABLE=1
            VULNERABLE_PACKAGES+=("$source|$package_name@$version")
            return 0
        fi
    done <<< "$vuln_versions"
    
    return 1
}

# Function to analyze a package-lock.json file
analyze_package_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}📂 Folder: $lockdir${NC}"
    echo -e "${GREEN}📄 File: $lockfile${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📦 Analyzing $lockfile..."
    
    PACKAGES=$(jq -r '
        ((.dependencies // {}) | to_entries[] | "\(.key)@\(.value.version)"),
        ((.packages // {}) | to_entries[] |
            select(.key | startswith("node_modules/")) |
            "\(.key | split("node_modules/")[-1])@\(.value.version)")
    ' "$lockfile" 2>/dev/null | sort -u)
    
    if [ -n "$PACKAGES" ]; then
        while IFS= read -r pkg_line; do
            if [[ "$pkg_line" =~ ^(.+)@(.+)$ ]]; then
                pkg_name="${BASH_REMATCH[1]}"
                pkg_version="${BASH_REMATCH[2]}"
                check_vulnerability "$pkg_name" "$pkg_version" "$lockfile" || true
            fi
        done <<< "$PACKAGES"
    fi
    echo ""
}

# Function to analyze a yarn.lock file
analyze_yarn_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}📂 Folder: $lockdir${NC}"
    echo -e "${GREEN}📄 File: $lockfile${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📦 Analyzing $lockfile..."
    
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
    echo ""
}

# Function to analyze a pnpm-lock.yaml file
analyze_pnpm_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}📂 Folder: $lockdir${NC}"
    echo -e "${GREEN}📄 File: $lockfile${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📦 Analyzing $lockfile..."
    
    if command -v yq &> /dev/null; then
        PACKAGES=$(yq eval '.packages | keys | .[]' "$lockfile" 2>/dev/null | grep '^/' | sed 's|^/||')
    else
        PACKAGES=$(grep -E "^\s+/" "$lockfile" 2>/dev/null | sed 's/^[[:space:]]*//' | sed 's/:$//' | sed 's|^/||')
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
    echo ""
}

# Function to analyze a bun.lock file
analyze_bun_lock() {
    local lockfile="$1"
    local lockdir=$(dirname "$lockfile")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}📂 Folder: $lockdir${NC}"
    echo -e "${GREEN}📄 File: $lockfile${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📦 Analyzing $lockfile..."
    
    PACKAGES=$(grep -E '^\s*"@?[^"]+@[^"]+",?$' "$lockfile" | sed 's/[",]//g' | sed 's/^[[:space:]]*//')
    
    if [ -n "$PACKAGES" ]; then
        while IFS= read -r pkg_line; do
            if [[ "$pkg_line" =~ ^(.+)@(.+)$ ]]; then
                pkg_name="${BASH_REMATCH[1]}"
                pkg_version="${BASH_REMATCH[2]}"
                check_vulnerability "$pkg_name" "$pkg_version" "$lockfile" || true
            fi
        done <<< "$PACKAGES"
    fi
    echo ""
}

# Main execution
main() {
    local use_default=true
    local use_config=true
    local custom_config=""
    local custom_sources=()
    
    # Parse command line arguments
    local current_csv_columns=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -u|--url)
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
        echo "  1. Create a .package-checker-config.json file"
        echo "  2. Use --url option to specify a vulnerability database URL"
        echo "  3. Use --config option to specify a custom configuration file"
        echo ""
        echo "Use --help for more information"
        exit 1
    fi
    
    local total_packages=$(echo "$VULN_DATA" | jq 'length')
    echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages${NC}"
    echo ""
    
    # Search for lockfiles
    echo "🔍 Searching for all lockfiles in the project (respecting .gitignore)..."
    
    TEMP_LOCKFILES=$(find . \( -name "package-lock.json" -o -name "npm-shrinkwrap.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" \) -type f ! -path "*/node_modules/*" ! -path "*/.yarn/*" ! -path "*/.git/*")
    
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
        echo "❌ No lockfiles found"
    else
        LOCKFILE_COUNT=$(echo "$LOCKFILES" | wc -l | tr -d ' ')
        echo "✅ $LOCKFILE_COUNT lockfile(s) found"
        echo ""
        
        echo "📋 List of found lockfiles:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        while IFS= read -r lockfile; do
            lockdir=$(dirname "$lockfile")
            lockname=$(basename "$lockfile")
            echo "  📁 $lockdir/"
            echo "     └─ $lockname"
        done <<< "$LOCKFILES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        echo "🔎 Starting lockfiles analysis..."
        echo ""
        
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
            esac
        done <<< "$LOCKFILES"
    fi
    
    echo ""
    
    # Search for package.json files
    echo "🔍 Searching for all package.json files in the project (respecting .gitignore)..."
    
    TEMP_FILES=$(find . -name "package.json" -type f ! -path "*/node_modules/*" ! -path "*/.yarn/*" ! -path "*/.git/*")
    
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
        echo "❌ No package.json files found"
    else
        PACKAGE_COUNT=$(echo "$PACKAGE_JSON_FILES" | wc -l | tr -d ' ')
        echo "✅ $PACKAGE_COUNT package.json file(s) found"
        echo ""
        
        echo "📋 List of found package.json files:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        while IFS= read -r package_file; do
            package_dir=$(dirname "$package_file")
            echo "  📁 $package_dir/"
            echo "     └─ package.json"
        done <<< "$PACKAGE_JSON_FILES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        echo "🔎 Starting dependencies analysis..."
        echo ""
        
        while IFS= read -r package_file; do
            package_dir=$(dirname "$package_file")
            
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo -e "${GREEN}📂 Folder being analyzed: $package_dir${NC}"
            echo -e "${GREEN}📄 File: $package_file${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            
            echo "📦 Analyzing declared dependencies in $package_file..."
            
            ALL_DEPS=$(jq -r '
                [
                    (.dependencies // {} | keys[]),
                    (.devDependencies // {} | keys[]),
                    (.optionalDependencies // {} | keys[]),
                    (.peerDependencies // {} | keys[])
                ] | unique | .[]
            ' "$package_file" 2>/dev/null)
            
            if [ -n "$ALL_DEPS" ]; then
                while IFS= read -r pkg_name; do
                    if echo "$VULN_DATA" | jq -e --arg pkg "$pkg_name" '.[$pkg]' > /dev/null 2>&1; then
                        vuln_versions=$(echo "$VULN_DATA" | jq -r --arg pkg "$pkg_name" '.[$pkg].vuln_vers | join(", ")')
                        echo -e "${YELLOW}⚠️  [$package_file] $pkg_name is in the list (vuln. versions: $vuln_versions)${NC}"
                        echo "   → Check your lockfile for the exact installed version"
                        FOUND_VULNERABLE=1
                    fi || true
                done <<< "$ALL_DEPS"
            else
                echo "   ℹ️  No dependencies found in this package.json"
            fi
            echo ""
        done <<< "$PACKAGE_JSON_FILES"
    fi
    
    echo ""
    echo "============================="
    if [ $FOUND_VULNERABLE -eq 0 ]; then
        echo -e "${GREEN}✅ No vulnerable packages detected${NC}"
    else
        echo -e "${RED}⚠️  WARNING: Vulnerable packages have been detected${NC}"
        echo ""
        echo "Vulnerable packages found:"
        echo ""
        
        current_file=""
        for vuln in "${VULNERABLE_PACKAGES[@]}"; do
            IFS='|' read -r file pkg <<< "$vuln"
            if [ "$file" != "$current_file" ]; then
                if [ -n "$current_file" ]; then
                    echo ""
                fi
                echo -e "${RED}📄 File: $file${NC}"
                current_file="$file"
            fi
            echo -e "${RED}   └─ $pkg${NC}"
        done
        echo ""
        
        echo -e "${YELLOW}Recommendations:${NC}"
        echo "   - Update to versions not listed in your vulnerability databases"
        echo "   - Check your CI/CD pipeline and generated artifacts"
    fi
    echo "============================="
    echo ""
    
    exit $FOUND_VULNERABLE
}

# Run main function
main "$@"