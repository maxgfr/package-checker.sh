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

