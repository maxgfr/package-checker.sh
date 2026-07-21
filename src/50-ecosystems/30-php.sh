# PHP (Composer) dependency parser.
#
#   composer.lock -> analyze_composer_lock
#
# composer.lock is plain JSON (no jq available/allowed on the scan path), and
# unlike package-lock.json's flat "node_modules/x": {...} map, its packages
# live in TWO top-level arrays: "packages" (production) and "packages-dev"
# (require-dev). Each array element is a package object with MANY sibling
# keys beyond name/version (source, dist, require, require-dev, provide,
# suggest, type, extra, autoload, notification-url, license, authors,
# description, homepage, keywords, support, funding, time, ...), several of
# which are themselves nested objects/arrays. Notably "authors" is an array
# of {"name": ..., "email": ..., ...} objects, so a naive "capture name, then
# capture the next version" state machine (as used for package-lock.json)
# would risk a nested author's "name" clobbering the package name, or -
# worse - would never be at risk of finding a stray "version" key deeper in
# (composer.lock has no "version" key inside require/source/dist/authors/
# support/funding), but relying on that emptily is fragile. Instead this
# parser tracks JSON brace/bracket DEPTH precisely (one increment per `{`/`[`,
# one decrement per `}`/`]`, quoted-string contents skipped so punctuation
# inside URLs/descriptions/names never miscounts) so that "name"/"version"
# are only captured when they are DIRECT fields of a package object (exactly
# one level below the "packages"/"packages-dev" array) - any subtable
# (source/dist/require/autoload/authors/support/funding/...) sits at least
# one level deeper and is excluded, mirroring the TOML [[package]] parser's
# subtable-gap hardening (src/50-ecosystems/20-rust.sh) but for JSON nesting
# instead of TOML headers. The pending name/version pair is emitted the
# instant the enclosing package object's closing brace is seen, so it does
# not matter how many nested keys/objects a real entry has in between.
#
# This depth-tracking approach assumes composer's own pretty-printed output
# (json_encode(..., JSON_PRETTY_PRINT): one token per line, exactly what
# `composer install`/`composer require` always produce), the same line-
# oriented assumption every other parser in this codebase makes.
#
# NORMALIZATION: package names are lowercased (composer canon is
# "vendor/package", already lowercase on the feed side - data/ghsa-composer.purl
# / data/osv-composer.purl - so this keeps a mixed-case lockfile entry, if
# one is ever seen in the wild, matching). Versions have a leading "v"
# stripped (some vendors tag "v7.4.0"; compare_versions_eco routes composer
# through the plain semver comparator, which expects a bare "7.4.0" - see
# src/40-versions/01-dispatch.sh) and "dev-*" branch aliases (e.g.
# "dev-master", "dev-feature/x" - not a resolvable release, no advisory can
# target it) are skipped silently, same as npm parsers skip workspace/link
# deps and pypi skips VCS entries without a resolvable version.
analyze_composer_lock() {
    local lockfile="$1"
    local eco="${2:-composer}"

    local vuln_count_before=${#VULNERABLE_PACKAGES[@]}

    local packages
    packages=$(awk '
    function emit_pkg() {
        if (pkg_name != "" && pkg_version != "") {
            print pkg_name "|" pkg_version
        }
        pkg_name = ""
        pkg_version = ""
    }
    BEGIN {
        depth = 0
        in_pkgs = 0
        pkg_depth = -1
    }
    {
        line = $0
        start_depth = depth

        # Enter a "packages" / "packages-dev" array at the CURRENT (pre-line)
        # depth. Guarded by !in_pkgs so the same literal text appearing
        # inside an already-open packages array (e.g. in a description
        # string) cannot re-trigger this.
        if (!in_pkgs && match(line, /"packages(-dev)?"[[:space:]]*:[[:space:]]*\[/)) {
            in_pkgs = 1
            pkg_depth = start_depth + 1
            pkg_name = ""
            pkg_version = ""
        }

        # Only DIRECT fields of a package object (one level below the array)
        # are candidate name/version lines; any nested object/array (source,
        # dist, require, provide, suggest, extra, autoload, authors,
        # support, funding, ...) sits at pkg_depth+2 or deeper and is
        # excluded by this check.
        if (in_pkgs && start_depth == pkg_depth + 1) {
            if (match(line, /^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "") pkg_name = tolower(temp)
            } else if (match(line, /^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"/)) {
                temp = line
                sub(/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"/, "", temp)
                sub(/".*$/, "", temp)
                if (temp != "" && temp !~ /^dev-/) {
                    sub(/^v/, "", temp)
                    pkg_version = temp
                }
            }
        }

        # Walk the line char-by-char (quoted-string contents skipped,
        # backslash-escape aware) to keep `depth` exact, emitting the
        # pending package the instant its object closes and closing the
        # array itself once depth falls back below pkg_depth.
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
                if (in_pkgs && depth == pkg_depth) {
                    emit_pkg()
                } else if (in_pkgs && depth < pkg_depth) {
                    in_pkgs = 0
                    pkg_depth = -1
                    pkg_name = ""
                    pkg_version = ""
                }
            }
        }
    }
    END { emit_pkg() }
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
