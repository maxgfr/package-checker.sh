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

    # First line: FEED_PKG_COUNT=N; the rest fills the lookup tables, merging
    # with every source loaded before.
    local first_line="${eval_commands%%$'\n'*}"
    local pkg_count="${first_line#*=}"
    eval "$eval_commands"

    echo -e "${GREEN}✅ Loaded ${pkg_count:-0} packages from $name${NC}"
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
