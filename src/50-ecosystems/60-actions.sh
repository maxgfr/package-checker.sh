# GitHub Actions workflow parser.
#
#   .github/workflows/*.yml | *.yaml -> analyze_github_workflow
#
# UNIQUE DISCOVERY: unlike every other ecosystem in this tool, GitHub Actions is
# selected by PATH, not by a lockfile basename — workflow files live at a
# well-known location (.github/workflows/) under arbitrary names. That hook is
# declared ONCE in PATH_ECOSYSTEM_REGISTRY (src/50-ecosystems/01-registry.sh);
# discover_project_files finds the files and the main() analysis loop routes
# them here via path_ecosystem_match(). This file only implements the analyzer.
#
# WHAT IS CHECKED: the `uses:` step references that pin a published action, i.e.
# `owner/repo@ref` or `owner/repo/subpath@ref` (the latter covers subpath
# actions and reusable-workflow calls like `org/repo/.github/workflows/x.yml@ref`).
# Both the plain mapping key (`uses: ...`) and the list-item form (`- uses: ...`)
# are handled, quoted ("...") or unquoted.
#
# SKIPPED by construction:
#   * local actions  — `./path` or `../path` (no published version to check)
#   * docker images  — `docker://image:tag` (not a GitHub Action release)
#   * versionless    — `uses: owner/repo` with no `@ref` (nothing to compare)
#   * non-action     — a value with no `owner/repo`-shaped `/` before the `@`
#
# NORMALIZATION (must match canon_purl_name's githubactions branch in
# src/31-parsers-purl.sh, which lowercases, and the feed emission): the name is
# `owner/repo[/subpath]` LOWERCASED. The version is the ref with a leading `v`
# stripped when it precedes a digit (`v4.1.1` -> `4.1.1`), matching go.sum/swift
# tag handling and the semver comparator (githubactions falls through
# compare_versions_eco's default npm-semver branch, src/40-versions/01-dispatch.sh).
# Branch refs (main, release) and 40-hex commit SHAs pass through unchanged; a
# SHA-pinned ref can then only ever EXACT-match a feed entry pinned to that same
# SHA — which is fine.
#
# LIMITATIONS (documented, intentional):
#   * The `uses: owner/repo@<sha> # vX.Y.Z` version-comment convention is NOT
#     parsed — the trailing comment is stripped and the SHA is used verbatim, so
#     a SHA-pinned action is only matched by an exact-SHA advisory, not by the
#     commented semver. Keeping comment parsing out avoids a brittle heuristic.
#   * A subpath ref (`github/codeql-action/analyze@v3`) is keyed by its FULL
#     `owner/repo/subpath` name; advisories published against the base repo
#     (`github/codeql-action`) therefore do not match a subpathed `uses:`.
#   * Best-effort line matching: a literal `uses: owner/repo@ref` line buried
#     inside a `run:` shell block would be treated as a step reference. This
#     mirrors the line-oriented approach of the other lockfile parsers.
analyze_github_workflow() {
    local lockfile="$1"
    local eco="${2:-githubactions}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    {
        line = $0
        gsub(/\r/, "", line)                    # tolerate CRLF checkouts

        # Only lines whose key is `uses:` (optionally a `- uses:` list item).
        if (line !~ /^[[:space:]]*-?[[:space:]]*uses[[:space:]]*:/) next

        # Strip everything up to and including the `uses:` key.
        val = line
        sub(/^[[:space:]]*-?[[:space:]]*uses[[:space:]]*:[[:space:]]*/, "", val)

        # Strip a trailing YAML comment (whitespace + # to EOL). Action refs
        # never contain a literal " #"; SHA-pin version comments are discarded.
        sub(/[[:space:]]+#.*$/, "", val)

        # Trim surrounding whitespace.
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)

        # Strip one layer of surrounding quotes (double or single).
        if (length(val) >= 2) {
            first = substr(val, 1, 1)
            last  = substr(val, length(val), 1)
            if ((first == "\"" && last == "\"") || (first == "'\''" && last == "'\''")) {
                val = substr(val, 2, length(val) - 2)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            }
        }

        if (val == "") next

        # Skip local actions (./ or ../) and docker image references.
        if (val ~ /^\.\.?\//) next
        if (val ~ /^docker:\/\//) next

        # Need an @ref to resolve a version; split at the LAST @ (refs never
        # contain @, and this is robust to any future name oddities).
        at = 0
        for (i = length(val); i >= 1; i--) {
            if (substr(val, i, 1) == "@") { at = i; break }
        }
        if (at <= 1) next
        name = substr(val, 1, at - 1)
        ref  = substr(val, at + 1)
        if (name == "" || ref == "") next

        # A real action reference is owner/repo[/subpath] — require the slash.
        # This drops stray `uses:` lines that are not action references.
        if (index(name, "/") == 0) next

        # Canonical GitHub Actions name: lowercased owner/repo[/subpath].
        name = tolower(name)

        # Version tag: strip a leading `v` before a digit (v1.2.3 -> 1.2.3).
        # Branch names and 40-hex commit SHAs pass through unchanged.
        if (ref ~ /^v[0-9]/) sub(/^v/, "", ref)

        if (name != "" && ref != "") print name "|" ref
    }
    ' "$lockfile" 2>/dev/null | sort -u)

    while IFS='|' read -r pkg_name version; do
        [ -z "$pkg_name" ] || [ -z "$version" ] && continue
        check_vulnerability "$eco" "$pkg_name" "$version" "$lockfile" || true
    done <<< "$packages"

    local vuln_count_after=${#VULNERABLE_PACKAGES[@]}
    if [ "$vuln_count_after" -eq "$vuln_count_before" ]; then
        echo -e "${GREEN}✓ [$lockfile] No vulnerabilities found${NC}"
    fi
}
