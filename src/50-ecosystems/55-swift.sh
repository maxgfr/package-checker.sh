# Swift Package Manager dependency parser.
#
#   Package.resolved -> analyze_package_resolved
#
# Package.resolved is plain JSON, in ONE of two shapes depending on the
# swift-tools-version that generated it:
#
#   v2/v3 (Swift 5.4+): pins live directly at the top level.
#     {
#       "pins" : [
#         {
#           "identity" : "swift-nio",
#           "kind" : "remoteSourceControl",
#           "location" : "https://github.com/apple/swift-nio.git",
#           "state" : { "revision" : "...", "version" : "2.10.0" }
#         }
#       ],
#       "version" : 2
#     }
#
#   v1 (swift-tools-version < 5.4): pins are nested one level deeper, under
#   "object", and the URL field is named "repositoryURL" instead of
#   "location" ("identity" is spelled "package" too, but neither name field
#   is ever read — see NORMALIZATION below).
#     {
#       "object" : { "pins" : [
#         { "package" : "swift-nio", "repositoryURL" : "https://github.com/apple/swift-nio.git",
#           "state" : { "branch" : null, "revision" : "...", "version" : "2.10.0" } }
#       ] },
#       "version" : 1
#     }
#
# Rather than branching on the top-level "version" field, this parser tracks
# brace/bracket DEPTH (the same technique packages.lock.json's parser uses,
# src/50-ecosystems/40-nuget.sh) starting from wherever the "pins" key is
# found — v1's extra "object" nesting simply shifts every depth down by one,
# which the relative tracking below absorbs for free, so both shapes are
# handled by ONE code path with no format sniffing. A pin's own direct
# fields (identity/package, kind, location/repositoryURL) are captured one
# level inside the array; its "state" sub-object is captured one level
# deeper still, where — matching either format — a `"version": "..."`
# QUOTED STRING field is required.
#
# Branch/revision-only pins (no released version — e.g. a dependency pinned
# to a branch or an exact commit) carry `"version": null` (v1) or omit the
# key entirely (v2/v3): neither satisfies the quoted-string match above, so
# ver stays empty and emit_pkg() skips the pin by construction — exactly
# like npm/dart/hex skip git/path/sdk-sourced deps that have no registry
# release to compare against advisories.
#
# NORMALIZATION (CRITICAL — must exactly match canon_purl_name's swift
# branch in src/31-parsers-purl.sh, and the feed emission in src/60-feeds.sh,
# since check_vulnerability performs no canonicalization of its own — see
# src/45-matching.sh): the package "name" checked against advisories is NOT
# the "identity"/"package" field (a short, human-picked label with no
# guaranteed uniqueness) but the resolved repository URL itself,
# canonicalized the same way GHSA/OSV swift feed rows are: strip a leading
# "http://" or "https://" scheme, strip a trailing ".git", lowercase the
# rest. E.g. "https://GitHub.com/Apple/Swift-NIO.git" becomes
# "github.com/apple/swift-nio". This makes matching resilient to
# mixed-case GitHub URLs (GitHub itself is case-insensitive) and to
# scheme/suffix variations across manifests.
#
# Versions fall through compare_versions_eco's default (npm-semver) branch —
# swift has no dedicated comparator, src/40-versions/01-dispatch.sh — with a
# leading "v" stripped first, same as go.sum/go.mod tags
# (src/50-ecosystems/15-go.sh), since Package.swift dependency pins commonly
# resolve against tags like "v2.10.0".
analyze_package_resolved() {
    local lockfile="$1"
    local eco="${2:-swift}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    function emit_pkg() {
        if (url != "" && ver != "") {
            canon = url
            sub(/^https?:\/\//, "", canon)
            sub(/\.git$/, "", canon)
            canon = tolower(canon)
            v = ver
            sub(/^v/, "", v)
            if (canon != "" && v != "") print canon "|" v
        }
        url = ""
        ver = ""
    }
    BEGIN {
        depth = 0
        in_pins = 0
        pins_depth = -1
    }
    {
        line = $0
        gsub(/\r/, "", line)                        # tolerate CRLF checkouts
        start_depth = depth

        # Enter the "pins" array wherever it appears (top level for v2/v3,
        # one level inside "object" for v1) — see header for why relative
        # depth tracking makes the two formats interchangeable here.
        if (!in_pins && match(line, /"pins"[[:space:]]*:[[:space:]]*\[/)) {
            in_pins = 1
            pins_depth = start_depth + 1
            url = ""
            ver = ""
        }

        # A pin object own direct fields, one level inside the array:
        # "location" (v2/v3) or "repositoryURL" (v1) carry the repo URL.
        if (in_pins && start_depth == pins_depth + 1) {
            if (match(line, /"location"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"location"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") url = temp
            } else if (match(line, /"repositoryURL"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"repositoryURL"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") url = temp
            }
        }

        # The pin nested "state" object, one level deeper still: only a
        # QUOTED "version" string counts — branch-only pins carry
        # "version": null (v1) or omit the key (v2/v3), neither of which
        # matches, so those pins fall through unresolved (see header).
        if (in_pins && start_depth == pins_depth + 2) {
            if (match(line, /"version"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^.*"version"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") ver = temp
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the
        # pending pin the instant its object closes (back to pins_depth),
        # and closing the "pins" array itself once depth falls below it.
        n = length(line)
        in_str = 0
        for (i = 1; i <= n; i++) {
            c = substr(line, i, 1)
            if (in_str) {
                if (c == "\\") { i++ }
                else if (c == "\"") { in_str = 0 }
                continue
            }
            if (c == "\"") { in_str = 1; continue }
            if (c == "{" || c == "[") {
                depth++
            } else if (c == "}" || c == "]") {
                depth--
                if (in_pins && depth == pins_depth) {
                    emit_pkg()
                } else if (in_pins && depth < pins_depth) {
                    in_pins = 0
                    pins_depth = -1
                    url = ""
                    ver = ""
                }
            }
        }
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
