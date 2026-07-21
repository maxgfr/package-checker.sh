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
