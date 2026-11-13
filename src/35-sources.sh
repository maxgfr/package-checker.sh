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

# Load data source. Optional arguments 5 and 6 (kind: ghsa, osv, runtime,
# custom (default) or lookup; ecosystem) describe it in the JSON report's
# "sources"; a lookup (--package-name) is not recorded. Optional arguments 7
# and 8, for a default feed: its origin when the file read is a download
# (the URL), and whether it is a stale copy.
load_data_source() {
    local url="$1"
    local format="${2:-}"
    local name="${3:-$url}"
    local csv_columns="${4:-}"
    local kind="${5:-custom}"
    local source_eco="${6:-}"
    local origin="${7:-$1}"
    local stale="${8:-false}"

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

    # A built-in feed always lists advisories: one without any purl line is
    # an empty file or something else (an HTML error or captive-portal page
    # served with 200), never a clean feed.
    case "$kind" in
        ghsa|osv|runtime)
            if [ "$FEED_RAW_COUNT" -eq 0 ]; then
                echo -e "${RED}❌ Error: $name has no advisory: $url is empty or not a feed${NC}"
                return 1
            fi
            ;;
    esac

    TOTAL_SOURCE_ENTRIES=$(( ${TOTAL_SOURCE_ENTRIES:-0} + FEED_RAW_COUNT ))
    if [ "$format" = purl ] && [ -n "${PREFILTER_TOKENS_FILE:-}" ]; then
        echo -e "${GREEN}✅ Loaded ${FEED_PKG_COUNT} packages from $name (${FEED_RAW_COUNT} entries before pre-filtering)${NC}"
    else
        echo -e "${GREEN}✅ Loaded ${FEED_PKG_COUNT} packages from $name${NC}"
    fi
    echo ""
    LOADED_SOURCE_COUNT=$((LOADED_SOURCE_COUNT + 1))
    if [ "$kind" != lookup ]; then
        local feed_file=""
        [ "$kind" = custom ] || feed_file="${url##*/}"
        record_feed_source "$kind" "$source_eco" "$feed_file" "$name" loaded "$origin" "$FEED_RAW_COUNT" "$url" "$stale"
    fi

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
        # An array without any non-empty entry keeps the built-in defaults.
        json_read_strings "$(json_get_array "$options_obj" "ignore_paths")"
        [ ${#JSON_STRINGS[@]} -eq 0 ] || CONFIG_IGNORE_PATHS=("${JSON_STRINGS[@]}")

        json_read_strings "$(json_get_array "$options_obj" "dependency_types")"
        [ ${#JSON_STRINGS[@]} -eq 0 ] || CONFIG_DEPENDENCY_TYPES=("${JSON_STRINGS[@]}")

        # Default-feed loading override; the CLI --ecosystems flag takes
        # precedence over this when both are set.
        json_read_strings "$(json_get_array "$options_obj" "ecosystems")"
        [ ${#JSON_STRINGS[@]} -eq 0 ] || CONFIG_ECOSYSTEMS="${JSON_STRINGS[*]}"

        # Runtime version check (Node.js, PHP): on unless "runtime_check": false
        local runtime_check_val=$(json_get_value "$options_obj" "runtime_check")
        [ "$runtime_check_val" != false ] || CONFIG_RUNTIME_CHECK=false
    fi
    
    # Parse config file and extract sources array
    local -a source_objs=()
    local source_obj
    while IFS= read -r source_obj; do
        source_objs+=("$source_obj")
    done < <(json_array_items "$(json_get_array "$config_content" "sources")")
    local sources_count=${#source_objs[@]}

    if [ "$load_sources" != true ]; then
        [ "$sources_count" -eq 0 ] || echo -e "${BLUE}ℹ️  Configuration sources ignored: sources given on the command line take precedence${NC}"
    elif [ "$sources_count" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Warning: No sources found in configuration file${NC}"
        # Don't return 1 here - config may still have github settings
    else
        local i url format name columns
        for ((i = 0; i < sources_count; i++)); do
            source_obj="${source_objs[$i]}"

            # Try to get url from "source" or "url" field
            url=$(json_get_value "$source_obj" "source")
            if [ -z "$url" ] || [ "$url" = "null" ]; then
                url=$(json_get_value "$source_obj" "url")
            fi
            if [ -z "$url" ] || [ "$url" = "null" ]; then
                echo -e "${RED}❌ Error: source $((i + 1)) of $config_path has no \"source\" or \"url\"${NC}"
                return 1
            fi

            format=$(json_get_value "$source_obj" "format")
            name=$(json_get_value "$source_obj" "name")
            columns=$(json_get_value "$source_obj" "columns")

            # Set default name if not provided
            if [ -z "$name" ] || [ "$name" = "null" ]; then
                name="Source $((i+1))"
            fi

            # Handle null/empty values
            [ "$format" != "null" ] || format=""
            [ "$columns" != "null" ] || columns=""

            load_data_source "$url" "$format" "$name" "$columns" || return 1
        done
    fi

    return 0
}
