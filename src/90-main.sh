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
    token_source_files | awk -v names="$*" '
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

# Files the pre-filter reads: the project files, a bun.lockb through its
# text form (a binary file would give wrong tokens; see prepare_bun_lockbs).
token_source_files() {
    local f
    case "$LOCKFILES" in
        *bun.lockb*) ;;
        *) printf '%s\n' "${LOCKFILES}${LOCKFILES:+$'\n'}${PACKAGE_JSON_FILES}"; return 0 ;;
    esac
    while IFS= read -r f; do
        if [ "${f##*/}" != bun.lockb ]; then
            printf '%s\n' "$f"
        elif [ -n "${BUN_LOCKB_TEXT[$f]+x}" ]; then
            printf '%s\n' "${BUN_LOCKB_TEXT[$f]}"
        fi
    done <<< "${LOCKFILES}${LOCKFILES:+$'\n'}${PACKAGE_JSON_FILES}"
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

# Print the path, as find reports it under DIR, of the macOS ~/Library when
# the home directory is DIR or below it; non-zero otherwise.
home_library_path() {
    local dir="$1" phys home rel base
    [ -n "${HOME:-}" ] && [ -d "$HOME/Library" ] || return 1
    phys=$(cd "$dir" 2>/dev/null && pwd -P) || return 1
    home=$(cd "$HOME" 2>/dev/null && pwd -P) || return 1
    case "$home" in
        "$phys") rel="" ;;
        "${phys%/}"/*) rel="${home#"${phys%/}"/}" ;;
        *) return 1 ;;
    esac
    base="${dir%/}"
    [ -z "$rel" ] || base="$base/$rel"
    printf '%s/Library\n' "$base"
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
        local pentry pglob nglobs ng gi
        local -a nglob_arr
        for pentry in "${selected_path_entries[@]}"; do
            # eco/parser/alias are unused here (dispatch happens later).
            IFS='|' read -r pglob nglobs _ <<< "$pentry"
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
    local -a default_prune_args=()
    if [ ${#match_args[@]} -gt 0 ]; then
        # -H: a scan root given as a symlink is followed (nothing below it).
        # -mindepth 1: the prune rules apply below the scan root, never to
        # the root itself (scanning ./.cache or ios/Pods on purpose).
        local -a find_args=( -H "$SEARCH_DIR" -mindepth 1 )
        local ignore_path home_library
        # Empty entries ("ignore_paths": [""]) are dropped first: an empty
        # "( )" group is a find syntax error that would hide every file.
        local -a prune_args=()
        for ignore_path in "${CONFIG_IGNORE_PATHS[@]}"; do
            ignore_path="${ignore_path%/}"
            [ -n "$ignore_path" ] || continue
            [ ${#prune_args[@]} -eq 0 ] || prune_args+=( -o )
            prune_args+=( -path "*/$ignore_path" )
        done
        # The default prune list is printed (-print) so the skipped trees can
        # be counted and listed; ignore_paths are pruned silently.
        if [ "$DEFAULT_PRUNE" = true ]; then
            for ignore_path in "${DEFAULT_PRUNE_PATHS[@]}"; do
                [ ${#default_prune_args[@]} -eq 0 ] || default_prune_args+=( -o )
                default_prune_args+=( -path "*/$ignore_path" )
            done
            # ~/Library: its children, except iCloud Drive (Mobile Documents)
            # and CloudStorage (Dropbox, Google Drive, OneDrive...), which
            # hold the user's own folders.
            if home_library=$(home_library_path "$SEARCH_DIR"); then
                default_prune_args+=( -o '(' -path "$home_library/*" ! -path "$home_library/*/*"
                    ! -path "$home_library/Mobile Documents" ! -path "$home_library/CloudStorage" ')' )
            fi
        fi
        if [ ${#prune_args[@]} -gt 0 ]; then
            find_args+=( '(' "${prune_args[@]}" ')' -prune -o )
        fi
        if [ ${#default_prune_args[@]} -gt 0 ]; then
            find_args+=( '(' "${default_prune_args[@]}" ')' -type d -prune -print -o )
        fi
        find_args+=( '(' "${match_args[@]}" ')' -type f -print )
        # An unreadable directory must not abort the scan (set -e): report it
        # and keep whatever was found. A failure that found nothing at all is
        # not a scan: stop instead of reporting a clean project.
        if ! found=$(find "${find_args[@]}" 2>/dev/null); then
            if [ -z "$found" ]; then
                echo -e "${RED}❌ Error: unable to search $SEARCH_DIR for project files${NC}" >&2
                exit "$EXIT_ERROR"
            fi
            echo -e "${YELLOW}⚠️  Warning: some directories under $SEARCH_DIR could not be read; results may be incomplete${NC}" >&2
            INCOMPLETE_REASONS+=("some directories under $SEARCH_DIR could not be read")
        fi
    fi

    # ---- Default-pruned directories ----
    # Printed by find next to the project files (which are regular files).
    if [ ${#default_prune_args[@]} -gt 0 ] && [ -n "$found" ]; then
        local kept_found="" line
        while IFS= read -r line; do
            if [ -d "$line" ]; then
                PRUNED_DIRS+=("$line")
            else
                kept_found+="${kept_found:+$'\n'}$line"
            fi
        done <<< "$found"
        found="$kept_found"
        if [ ${#PRUNED_DIRS[@]} -gt 0 ]; then
            echo -e "${BLUE}ℹ️  Skipping ${#PRUNED_DIRS[@]} cache, package-store or build directory(ies) (use --no-default-prune to scan them):${NC}"
            printf '      %s\n' "${PRUNED_DIRS[@]:0:10}"
            [ ${#PRUNED_DIRS[@]} -le 10 ] || echo "      ... and $(( ${#PRUNED_DIRS[@]} - 10 )) more"
            echo ""
        fi
    fi

    # ---- Git-ignored files ----
    # A git-ignored lockfile is often what is installed (libraries ignore
    # their lockfile): they are scanned, and counted. --exclude-gitignored
    # skips and lists them. The repository is the one containing the scanned
    # directory (not the current one), checked once for all files. Files
    # fetched from GitHub are never filtered: the output directory itself is
    # often git-ignored.
    if [ -n "$found" ] && [ "$SEARCH_DIR" != "$GITHUB_OUTPUT_DIR" ] &&
        git -C "$SEARCH_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        # NUL-separated in and out (-z): git would C-quote names with quotes
        # or non-ASCII characters ("caf\303\251/..."), which then match no
        # discovered path.
        local prefix="${SEARCH_DIR%/}/" f rel
        local -a ignored=()
        local -A ignored_set=()
        while IFS= read -r -d '' rel; do
            ignored+=("$rel")
            ignored_set["$rel"]=1
        done < <(while IFS= read -r f; do printf '%s\0' "${f#"$prefix"}"; done <<< "$found" |
            git -C "$SEARCH_DIR" check-ignore -z --stdin 2>/dev/null || true)
        if [ ${#ignored[@]} -gt 0 ]; then
            if [ "$exclude_gitignored" = true ]; then
                local kept_found="" skipped=0
                while IFS= read -r f; do
                    rel="${f#"$prefix"}"
                    if [ -n "${ignored_set[$rel]+x}" ]; then
                        skipped=$((skipped + 1))
                    else
                        kept_found+="${kept_found:+$'\n'}$f"
                    fi
                done <<< "$found"
                found="$kept_found"
                GITIGNORED_SKIPPED="$skipped"
                echo -e "${YELLOW}⚠️  Skipping $skipped git-ignored file(s) (--exclude-gitignored):${NC}"
            else
                GITIGNORED_SCANNED="${#ignored[@]}"
                echo -e "${BLUE}ℹ️  Scanning ${#ignored[@]} git-ignored file(s) (use --exclude-gitignored to skip them):${NC}"
            fi
            printf '      %s\n' "${ignored[@]:0:10}"
            [ ${#ignored[@]} -le 10 ] || echo "      ... and $(( ${#ignored[@]} - 10 )) more"
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

    # bun.lockb files are converted to text first: one that cannot be read
    # does not cover its package.json (below).
    prepare_bun_lockbs

    # ---- package.json files already covered by a lockfile ----
    # A lockfile pins what is installed; the manifest only declares ranges
    # (lodash ^4.17.0 would be checked as 4.17.0 while the lock has 4.18.1).
    # Skip a package.json whose directory holds an npm-family lockfile, or
    # whose ancestor (up to the scan root) is a workspace root with one. A
    # lockfile that cannot be read (unreadable, or a bun.lockb bun could not
    # print) covers nothing: the manifest is scanned instead, and the
    # lockfile is still reported as not scanned.
    SKIPPED_PACKAGE_JSON_COUNT=0
    if [ -n "$PACKAGE_JSON_FILES" ] && [ -n "$LOCKFILES" ]; then
        local -A npm_lock_dirs=()
        local lf
        while IFS= read -r lf; do
            [ -r "$lf" ] || continue
            case "${lf##*/}" in
                bun.lockb)
                    [ -z "${BUN_LOCKB_TEXT[$lf]+x}" ] || npm_lock_dirs["${lf%/*}"]=1 ;;
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
                # Parsed once: analyze_cyclonedx_inventory reuses the list.
                SBOM_COMPONENTS["$lfile"]=$(cyclonedx_components "$lfile")
                for e in $(printf '%s\n' "${SBOM_COMPONENTS[$lfile]}" | cut -d'|' -f1 | sort -u); do
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
    UNREADABLE_FILES+=("$1")
}

# A parser that fails (awk or sort killed, out of memory) read nothing
# reliable: the file was not scanned. Listed with the unreadable files, with
# its own reason; the "no package could be read" warning is not added.
report_parser_failure() {
    echo -e "${RED}❌ [$1] Could not be parsed (the parser failed): it was not scanned${NC}"
    LOCKFILE_SKIPPED=1
    UNREADABLE_FILES+=("$1")
    INCOMPLETE_REASONS+=("$1 could not be parsed: it was not scanned")
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
    local exclude_gitignored=false
    local update_feeds_requested=false data_dir_flag=false max_feed_age_flag=false

    # Any unexpected failure that aborts the run (set -e) exits with
    # EXIT_ERROR, never with 1, which means "vulnerable packages found".
    # Command substitutions keep their usual non-fatal behavior.
    set -E
    trap '[ "$BASH_SUBSHELL" -ne 0 ] || exit "$EXIT_ERROR"' ERR

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--source|-f|--format|--csv-columns|-c|--config|--github-org|--github-repo|--github-token|--github-output|--package-name|--package-version|--ecosystem|--ecosystems|--lockfile-types|--sbom|--data-dir|--max-feed-age)
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
            --default-source-ghsa|--default-source-osv|--default-source-ghsa-osv)
                # Record intent; the feed is resolved per detected ecosystem
                # after project discovery (see the source-loading section).
                # The flags add up: --default-source-ghsa --default-source-osv
                # loads both feeds.
                local wanted_feed
                for wanted_feed in ghsa osv; do
                    case "$1" in *"-$wanted_feed"*) ;; *) continue ;; esac
                    case " $default_feeds " in
                        *" $wanted_feed "*) ;;
                        *) default_feeds="${default_feeds:+$default_feeds }$wanted_feed" ;;
                    esac
                done
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
                    # Ecosystem names win; otherwise an existing directory
                    # named without a slash ("data") is the output directory.
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"
                       if ! feed_resolve_types "${_fetch_ecos[@]}" 2>/dev/null && [ -d "$2" ]; then
                           FEED_OUTPUT_DIR="$2" fetch_osv
                       else fetch_osv "${_fetch_ecos[@]}"; fi ;;
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
                    # Ecosystem names win; otherwise an existing directory
                    # named without a slash ("data") is the output directory.
                    *) IFS=', ' read -ra _fetch_ecos <<< "$2"
                       if ! feed_resolve_types "${_fetch_ecos[@]}" 2>/dev/null && [ -d "$2" ]; then
                           FEED_OUTPUT_DIR="$2" fetch_ghsa
                       else fetch_ghsa "${_fetch_ecos[@]}"; fi ;;
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
                # Git-ignored files are scanned by default; kept for compatibility.
                shift
                ;;
            --exclude-gitignored)
                exclude_gitignored=true
                shift
                ;;
            --no-default-prune)
                DEFAULT_PRUNE=false
                shift
                ;;
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --data-dir)
                FEED_DATA_DIR="$2"
                data_dir_flag=true
                shift 2
                ;;
            --max-feed-age)
                if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}❌ Error: --max-feed-age takes a number of days (0 = no limit)${NC}"
                    exit "$EXIT_ERROR"
                fi
                MAX_FEED_AGE_DAYS=$((10#$2))
                max_feed_age_flag=true
                shift 2
                ;;
            --update-feeds)
                update_feeds_requested=true
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

    # A feed directory that does not exist would be skipped without a word
    # (--update-feeds creates it). The flag is an error; the environment
    # variable may be exported before the directory is first filled: a
    # warning.
    if [ -n "$FEED_DATA_DIR" ] && [ ! -d "$FEED_DATA_DIR" ] && [ "$update_feeds_requested" = false ]; then
        if [ "$data_dir_flag" = true ]; then
            echo -e "${RED}❌ Error: --data-dir $FEED_DATA_DIR is not a directory (create it with --update-feeds --data-dir DIR)${NC}" >&2
            exit "$EXIT_ERROR"
        fi
        echo -e "${YELLOW}⚠️  Warning: PACKAGE_CHECKER_DATA_DIR=$FEED_DATA_DIR is not a directory; ignored${NC}" >&2
        FEED_DATA_DIR=""
    fi

    # PACKAGE_CHECKER_MAX_FEED_AGE: the default of --max-feed-age (the full
    # Docker image sets 0: its feeds are those of the image build).
    if [ "$max_feed_age_flag" = false ] && [ -n "${PACKAGE_CHECKER_MAX_FEED_AGE:-}" ]; then
        if [[ "$PACKAGE_CHECKER_MAX_FEED_AGE" =~ ^[0-9]+$ ]]; then
            MAX_FEED_AGE_DAYS=$((10#$PACKAGE_CHECKER_MAX_FEED_AGE))
        else
            echo -e "${YELLOW}⚠️  Warning: PACKAGE_CHECKER_MAX_FEED_AGE=$PACKAGE_CHECKER_MAX_FEED_AGE is not a number of days; ignored${NC}" >&2
        fi
    fi

    # --update-feeds: refresh the feeds of --data-dir, then stop.
    if [ "$update_feeds_requested" = true ]; then
        if [ -z "$FEED_DATA_DIR" ]; then
            echo -e "${RED}❌ Error: --update-feeds needs --data-dir DIR (or PACKAGE_CHECKER_DATA_DIR)${NC}"
            exit "$EXIT_ERROR"
        fi
        local update_types="" update_token update_status=0
        if [ -n "$cli_ecosystems" ]; then
            for update_token in ${cli_ecosystems//,/ }; do
                update_token=$(ecosystem_alias_to_purl "$update_token")
                [ "$update_token" != runtime ] || continue
                case " $update_types " in *" $update_token "*) ;; *) update_types="${update_types:+$update_types }$update_token" ;; esac
            done
        else
            update_types=$(feed_all_types)
        fi
        echo "Updating feeds in $FEED_DATA_DIR..."
        update_feeds "$FEED_DATA_DIR" "$update_types" || update_status=$?
        case "$update_status" in
            0) exit 0 ;;
            1) exit "$EXIT_INCOMPLETE" ;;
            *) exit "$EXIT_ERROR" ;;
        esac
    fi

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
        prepare_default_source_lookup
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

        local eco feed feed_file feed_label
        for eco in $feed_ecos; do
            # Runtime advisories have a single feed of their own (step 3b).
            [ "$eco" != runtime ] || continue
            for feed in $feeds_to_load; do
                feed_file=$(default_feed_filename "$feed" "$eco")
                feed_label=$(printf '%s' "$feed" | tr '[:lower:]' '[:upper:]')
                # Runs in this shell (no command substitution): the lookup
                # state (clock, Homebrew prefix, write directory) is kept.
                resolve_default_feed "$feed_file" || true
                if [ -z "$FEED_PATH" ] && [ "$FEED_FAILURE" = missing ]; then
                    echo -e "${YELLOW}⚠️  Warning: Unable to find ${feed} feed for ${eco} (${feed_file})${NC}"
                    record_feed_source "$feed" "$eco" "$feed_file" "Default ${feed_label} Source" missing ""
                    INCOMPLETE_REASONS+=("the $feed feed for $eco ($feed_file) could not be found")
                    continue
                fi
                # A feed that cannot be downloaded or read, or holds no
                # advisory, leaves its advisories out: the scan goes on,
                # reported incomplete.
                if [ -n "$FEED_PATH" ]; then
                    feed_using_line "$feed_label"
                    if load_data_source "$FEED_PATH" "purl" "Default ${feed_label} Source" "" "$feed" "$eco" \
                        "$FEED_ORIGIN" "$FEED_STALE"; then
                        sources_loaded=true
                        continue
                    fi
                fi
                record_feed_source "$feed" "$eco" "$feed_file" "Default ${feed_label} Source" failed "$FEED_ORIGIN"
                INCOMPLETE_REASONS+=("the $feed feed for $eco could not be loaded from $FEED_ORIGIN")
            done
        done
    fi

    # 3b. Runtime advisories (Node.js, PHP): one feed, loaded whenever the
    #     project pins a runtime version, whatever the GHSA/OSV choice.
    local runtime_feed_loaded=false
    if { [ "$runtime_check" != false ] && [ -n "$RUNTIME_FILES" ]; } ||
        { [ -n "$name" ] && [ "$ecosystem" = runtime ]; }; then
        resolve_default_feed "osv-runtime.purl" || true
        if [ -z "$FEED_PATH" ] && [ "$FEED_FAILURE" = missing ]; then
            echo -e "${YELLOW}⚠️  Warning: Unable to find the runtime feed (osv-runtime.purl); runtime versions are not checked${NC}"
            record_feed_source runtime runtime osv-runtime.purl "Runtime advisories (Node.js, PHP)" missing ""
            INCOMPLETE_REASONS+=("the runtime feed (osv-runtime.purl) could not be found: runtime versions were not checked")
        else
            if [ -n "$FEED_PATH" ]; then
                feed_using_line runtime
                if load_data_source "$FEED_PATH" "purl" "Runtime advisories (Node.js, PHP)" "" runtime runtime \
                    "$FEED_ORIGIN" "$FEED_STALE"; then
                    sources_loaded=true
                    runtime_feed_loaded=true
                fi
            fi
            if [ "$runtime_feed_loaded" = false ]; then
                record_feed_source runtime runtime osv-runtime.purl "Runtime advisories (Node.js, PHP)" failed "$FEED_ORIGIN"
                INCOMPLETE_REASONS+=("the runtime feed could not be loaded from $FEED_ORIGIN: runtime versions were not checked")
            fi
        fi
    fi

    # 4. --package-name: check the exact version itself, then add the lookup
    #    entry (loaded last so the version check cannot match it).
    if [ -n "$name" ]; then
        if [ -n "$package_version" ] && [[ "$package_version" != *[\ \<\>=\^~*,\|]* ]]; then
            check_vulnerability "$ecosystem" "$CANON_NAME" "$package_version" "--package-name" || true
        fi
        load_data_source "$package_lookup_file" "purl" "Package lookup: $name" "" lookup || exit "$EXIT_ERROR"
        sources_loaded=true
    fi

    # Every requested feed is missing or failed: nothing can be checked. Like
    # one missing feed, it is an incomplete scan (exit 3), said on stderr with
    # each reason, and the reports are written so no older one is left behind.
    if [ "$sources_loaded" = false ]; then
        {
            echo -e "${RED}❌ Error: Unable to find any vulnerability data source${NC}"
            echo ""
            echo "Tried the following locations for each detected ecosystem:"
            echo "  - --data-dir DIR (or PACKAGE_CHECKER_DATA_DIR)"
            echo "  - Next to the script: <script dir>/data/"
            echo "  - Homebrew: \$(brew --prefix)/share/package-checker/data/"
            echo "  - Docker: /app/data/"
            echo "  - Remote: $FEED_REMOTE_BASE/"
            echo "  - Local: ./data/"
            echo ""
            echo "Download the feeds with --update-feeds --data-dir DIR, or give a data source"
            echo "with --source <URL> or a .package-checker.config.json file (see --help)."
        } >&2
        [ ${#INCOMPLETE_REASONS[@]} -gt 0 ] || INCOMPLETE_REASONS+=("no vulnerability data source could be loaded")
        write_reports
        report_incomplete
        exit "$EXIT_INCOMPLETE"
    fi

    # --strict: a requested feed that is missing stops the run before the scan.
    if [ "$STRICT_MODE" = true ] && [ ${#INCOMPLETE_REASONS[@]} -gt 0 ]; then
        echo -e "${RED}❌ --strict: the scan would be incomplete; nothing was scanned${NC}"
        write_reports
        report_incomplete
        exit "$EXIT_INCOMPLETE"
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
            local checked_before="${CHECKED_PACKAGE_COUNT:-0}"
            LOCKFILE_SKIPPED=0   # set by a parser that defers to another file
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
                # A workflow without a published action is ordinary.
                lock_parser=""
            fi
            # A lockfile with content that yields no package at all is either
            # empty of dependencies or in a shape the parser does not read:
            # say so instead of letting "no vulnerabilities" imply a check.
            if [ -n "$lock_parser" ] && [ "$LOCKFILE_SKIPPED" = 0 ] &&
                [ "${CHECKED_PACKAGE_COUNT:-0}" = "$checked_before" ] &&
                grep -q '[^[:space:]]' "$lockfile" 2>/dev/null; then
                echo -e "${YELLOW}⚠️  [$lockfile] No package could be read from this file (no dependency, or an unsupported format)${NC}"
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
            deps=$(set -o pipefail; awk -v dep_pattern="$dep_types_pattern" '
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
            ' "$package_file" 2>/dev/null | sort -u) || { report_parser_failure "$package_file"; continue; }

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

        # Display grouped results (read line by line: a key may hold spaces
        # or glob characters, e.g. an SBOM version "1.0 beta")
        local -a group_keys=()
        while IFS= read -r pkg; do
            group_keys+=("$pkg")
        done < <(printf '%s\n' "${!pkg_files[@]}" | sort -u)
        for pkg in "${group_keys[@]}"; do
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

    # An unreadable or unsupported project file, or an organization
    # repository that could not be fetched, makes the result incomplete.
    [ "$UNREADABLE_FILE_COUNT" -eq 0 ] ||
        INCOMPLETE_REASONS+=("$UNREADABLE_FILE_COUNT project file(s) could not be read")
    [ "${GITHUB_FAILED_REPOS:-0}" -eq 0 ] ||
        INCOMPLETE_REASONS+=("$GITHUB_FAILED_REPOS repository(ies) could not be fetched")

    # Export results if requested (also when empty: see export_vulnerabilities_json)
    write_reports
    report_incomplete

    # 1 (vulnerable) wins over 3 (incomplete), except with --strict.
    if [ ${#INCOMPLETE_REASONS[@]} -gt 0 ] && { [ "$FOUND_VULNERABLE" -eq 0 ] || [ "$STRICT_MODE" = true ]; }; then
        exit "$EXIT_INCOMPLETE"
    fi
    exit $FOUND_VULNERABLE
}

# Write the JSON / CSV reports requested by main (its export_*_file locals,
# through bash dynamic scope).
write_reports() {
    if [ -n "$export_json_file" ]; then
        echo ""
        export_vulnerabilities_json "$export_json_file" || exit "$EXIT_ERROR"
    fi
    if [ -n "$export_csv_file" ]; then
        echo ""
        export_vulnerabilities_csv "$export_csv_file" || exit "$EXIT_ERROR"
    fi
}

# Say on stderr why the scan is incomplete (nothing when it is complete).
report_incomplete() {
    [ ${#INCOMPLETE_REASONS[@]} -gt 0 ] || return 0
    local reason
    echo -e "${RED}❌ Scan incomplete:${NC}" >&2
    for reason in "${INCOMPLETE_REASONS[@]}"; do
        echo -e "${RED}   • $reason${NC}" >&2
    done
}
