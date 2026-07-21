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
# GitHub Actions is discovered by PATH (.github/workflows/*.yml|*.yaml), not by
# a fixed lockfile basename, so it is declared in the parallel
# PATH_ECOSYSTEM_REGISTRY below — NOT as a row in this table, whose derivations
# all assume a fixed filename (find `-name`, basename dispatch, and the GitHub
# code-search filename list). This file is the ONE place both registries live;
# discover_project_files and the main() dispatch loop special-case path entries
# via path_ecosystem_match (parser: src/50-ecosystems/60-actions.sh).
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
    "requirements.txt|pypi|analyze_requirements_txt|python"
    "poetry.lock|pypi|analyze_toml_pkg_lock|python"
    "uv.lock|pypi|analyze_toml_pkg_lock|python"
    "pdm.lock|pypi|analyze_toml_pkg_lock|python"
    "Pipfile.lock|pypi|analyze_pipfile_lock|python"
    "Gemfile.lock|gem|analyze_gemfile_lock|ruby"
    "composer.lock|composer|analyze_composer_lock|php"
    "gradle.lockfile|maven|analyze_gradle_lockfile|maven"
    "pom.xml|maven|analyze_pom_xml|maven"
    "packages.lock.json|nuget|analyze_nuget_lock|nuget"
    "pubspec.lock|pub|analyze_pubspec_lock|dart"
    "mix.lock|hex|analyze_mix_lock|hex"
    "Package.resolved|swift|analyze_package_resolved|swift"
)

# ============================================================================
# Path-discovered ecosystems — the parallel to ECOSYSTEM_REGISTRY for
# ecosystems selected by a directory PATH pattern instead of a fixed lockfile
# basename. GitHub Actions is the only one: workflow YAML lives at a well-known
# path (.github/workflows/*.yml|*.yaml) under ARBITRARY filenames, so `find
# -name` cannot select it and `basename` cannot dispatch it. Both the find-args
# builder and the dispatcher special-case these entries (see discover_project_files
# and the analysis loop in src/90-main.sh); path_ecosystem_match() below is the
# single resolver they share.
#
# Each entry: "path-glob|name-globs|purl-type|parser-function|type-alias"
#   path-glob        find -path pattern selecting the containing directory
#   name-globs       comma-separated -name patterns (OR-ed) for the filename
#   purl-type        ecosystem namespace (as in ECOSYSTEM_REGISTRY)
#   parser-function  analyzer invoked as: <fn> <file> <purl-type>
#   type-alias       user-facing --lockfile-types / --ecosystems name
#
# NOTE: path ecosystems are deliberately absent from ecosystem_scan_filenames()
# (the GitHub org-scan search) — matching arbitrary-named workflow YAML across a
# whole repo tree via the code-search API is too noisy — so GitHub org scanning
# does not fetch workflow files. This is a documented limitation.
PATH_ECOSYSTEM_REGISTRY=(
    "*/.github/workflows/*|*.yml,*.yaml|githubactions|analyze_github_workflow|actions"
)

# Resolve a discovered file to its path-ecosystem. Echoes "parser|eco|alias"
# for the FIRST PATH_ECOSYSTEM_REGISTRY entry whose path-glob matches $1 and one
# of whose name-globs matches its basename; returns non-zero with no output when
# nothing matches. Shared by the detection loop and the dispatcher so a workflow
# file routes to its analyzer without a basename key. `case` patterns are used
# (not filesystem globbing): the name-globs are read via IFS to avoid pathname
# expansion, and `$glob`/`$path_glob` act as pattern metacharacters in `case`.
path_ecosystem_match() {
    # NB: separate declarations — `local file=.. base=${file##*/}` would expand
    # base against file's OUTER value (bash evaluates all `local` args before
    # assigning), yielding an empty basename.
    local file="$1"
    local base="${file##*/}"
    local entry path_glob name_globs eco parser alias glob
    local -a globs
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r path_glob name_globs eco parser alias <<< "$entry"
        # SC2254: $path_glob is INTENTIONALLY unquoted so it acts as a glob
        # pattern (e.g. */.github/workflows/*), not a literal string.
        # shellcheck disable=SC2254
        case "$file" in
            $path_glob) ;;
            *) continue ;;
        esac
        IFS=',' read -ra globs <<< "$name_globs"
        for glob in "${globs[@]}"; do
            # SC2254: $glob is INTENTIONALLY unquoted so *.yml / *.yaml match as
            # patterns rather than literal filenames.
            # shellcheck disable=SC2254
            case "$base" in
                $glob) printf '%s|%s|%s\n' "$parser" "$eco" "$alias"; return 0 ;;
            esac
        done
    done
    return 1
}

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

    # Path-discovered ecosystems contribute their type-alias to the known list
    # too (so --lockfile-types actions and --ecosystems actions validate), but
    # NO basename rows in the LOCKFILE_* maps — they dispatch by path via
    # path_ecosystem_match(), not by a basename lookup.
    local pglob nglobs
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r pglob nglobs eco parser alias <<< "$entry"
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
    local token="$1" entry basename eco parser alias pglob nglobs
    for entry in "${ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r basename eco parser alias <<< "$entry"
        if [ "$token" = "$alias" ]; then
            printf '%s\n' "$eco"
            return 0
        fi
    done
    # Path-discovered ecosystems (e.g. actions -> githubactions).
    for entry in "${PATH_ECOSYSTEM_REGISTRY[@]}"; do
        IFS='|' read -r pglob nglobs eco parser alias <<< "$entry"
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
