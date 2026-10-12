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
# lockfile_types, only_package_json, only_lockfiles, use_github) via bash
# dynamic scope; sets SEARCH_DIR/LOCKFILES/PACKAGE_JSON_FILES as globals.
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
    if [ "$want_pj" = true ]; then
        [ ${#match_args[@]} -gt 0 ] && match_args+=( -o )
        match_args+=( -name "package.json" )
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
    if [ -n "$found" ] && [ "$SEARCH_DIR" != "$GITHUB_OUTPUT_DIR" ] &&
        git -C "$SEARCH_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        local prefix="${SEARCH_DIR%/}/" ignored
        ignored=$(printf '%s\n' "$found" | while IFS= read -r f; do printf '%s\n' "${f#"$prefix"}"; done |
            git -C "$SEARCH_DIR" check-ignore --stdin 2>/dev/null) || true
        if [ -n "$ignored" ]; then
            found=$(printf '%s\n' "$found" | awk -v prefix="$prefix" '
                NR == FNR { ignored[$0] = 1; next }
                { rel = $0; if (index(rel, prefix) == 1) rel = substr(rel, length(prefix) + 1) }
                !(rel in ignored)' <(printf '%s\n' "$ignored") -)
        fi
    fi

    # ---- Split lockfiles from package.json files ----
    LOCKFILES=""
    PACKAGE_JSON_FILES=""
    local file
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        if [ "${file##*/}" = "package.json" ] && [ "$want_pj" = true ]; then
            PACKAGE_JSON_FILES+="${PACKAGE_JSON_FILES:+$'\n'}$file"
        elif [ "${file##*/}" != "package.json" ]; then
            LOCKFILES+="${LOCKFILES:+$'\n'}$file"
        fi
    done <<< "$found"

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

    # Any unexpected failure that aborts the run (set -e) exits with
    # EXIT_ERROR, never with 1, which means "vulnerable packages found".
    # Command substitutions keep their usual non-fatal behavior.
    set -E
    trap '[ "$BASH_SUBSHELL" -ne 0 ] || exit "$EXIT_ERROR"' ERR

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--source|-f|--format|--csv-columns|-c|--config|--github-org|--github-repo|--github-token|--github-output|--package-name|--package-version|--ecosystem|--ecosystems|--lockfile-types)
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
        npm|pypi|golang|maven|cargo|gem|composer|nuget|pub|hex|swift|githubactions)
            ;;
        *)
            echo -e "${RED}❌ Error: Unsupported ecosystem '$ecosystem'${NC}"
            echo "Valid ecosystems: npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions"
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

    # Discover project files and detect ecosystems BEFORE loading feeds, so we
    # only pull the default feeds the detected ecosystems actually need. This
    # step is silent; the results are printed/analyzed after the lookup build.
    discover_project_files

    # A truncated project file is an incomplete scan, never a clean result.
    # Validate strict JSON only: bun.lock is JSONC and has a separate grammar.
    local project_input
    while IFS= read -r project_input; do
        [ -z "$project_input" ] && continue
        case "${project_input##*/}" in
            package.json|package-lock.json|npm-shrinkwrap.json|Pipfile.lock|composer.lock|packages.lock.json|Package.resolved|deno.lock)
                if ! json_is_valid_file "$project_input"; then
                    echo -e "${RED}❌ Invalid JSON in project file: $project_input${NC}"
                    exit "$EXIT_ERROR"
                fi
                ;;
        esac
    done <<< "${LOCKFILES}${LOCKFILES:+$'\n'}${PACKAGE_JSON_FILES}"

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

    echo -e "${BLUE}📊 Total unique vulnerable packages: $total_packages${NC}"

    # If there are no vulnerability entries loaded, stop early — nothing to scan
    if [ "$total_packages" -eq 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  No vulnerability data loaded. Nothing to scan, exiting.${NC}"
        exit 0
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

            print_advisories "${VULN_ADVISORIES[$pkg]:-}" && echo ""

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

    exit $FOUND_VULNERABLE
}
