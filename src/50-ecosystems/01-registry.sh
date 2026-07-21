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
# NOTE: GitHub Actions support (a later task) matches by PATH
# (.github/workflows/*.yml), not by a basename, so it will register through a
# dedicated path-based discovery hook rather than a row in this table.
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
)

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
    local token="$1" entry basename eco parser alias
    for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r basename eco parser alias <<< "$entry"
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
