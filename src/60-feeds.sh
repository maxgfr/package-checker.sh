# ============================================================================
# Vulnerability Feed Generation Functions
# ============================================================================
#
# Feeds are generated from two upstream sources, both using the OSV schema:
#   - GHSA:  a single sparse clone of github/advisory-database, scanned once,
#            emitting PURL lines for every supported ecosystem at once.
#   - OSV:   one all.zip per ecosystem from the OSV GCS bucket.
#
# jq is REQUIRED here (fetch path only); the scan path stays jq-free.
#
# FEED_ECOSYSTEM_MAP is the single source of truth mapping:
#   purl-type | OSV/GHSA ecosystem string | OSV zip directory (URL-encoded)
#
# The "ecosystem string" is matched against .affected[].package.ecosystem in the
# advisory JSON; the "zip directory" is the path segment used to fetch
# https://osv-vulnerabilities.storage.googleapis.com/<dir>/all.zip .
#
# Empirically verified (HEAD requests to the OSV bucket + ecosystems.txt index +
# real advisory JSON): all 12 directories return 200 and the ecosystem strings
# below match the upstream data exactly (notably "SwiftURL" and "GitHub Actions").
# ============================================================================
FEED_ECOSYSTEM_MAP=(
    "npm|npm|npm"
    "pypi|PyPI|PyPI"
    "golang|Go|Go"
    "maven|Maven|Maven"
    "cargo|crates.io|crates.io"
    "gem|RubyGems|RubyGems"
    "composer|Packagist|Packagist"
    "nuget|NuGet|NuGet"
    "pub|Pub|Pub"
    "hex|Hex|Hex"
    "swift|SwiftURL|SwiftURL"
    "githubactions|GitHub Actions|GitHub%20Actions"
)

# Space-separated list of every supported purl type, in table order.
feed_all_types() {
    local entry types=""
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        types="${types:+$types }${entry%%|*}"
    done
    printf '%s' "$types"
}

# Print the OSV/GHSA ecosystem string for a purl type (empty if unsupported).
feed_eco_string() {
    local type="$1" entry t eco dir
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        IFS='|' read -r t eco dir <<< "$entry"
        if [ "$t" = "$type" ]; then printf '%s' "$eco"; return 0; fi
    done
    return 0
}

# Print the OSV zip directory (URL-encoded) for a purl type.
feed_osv_dir() {
    local type="$1" entry t eco dir
    for entry in "${FEED_ECOSYSTEM_MAP[@]}"; do
        IFS='|' read -r t eco dir <<< "$entry"
        if [ "$t" = "$type" ]; then printf '%s' "$dir"; return 0; fi
    done
    return 0
}

# Build a JSON object mapping {ecosystem-string: purl-type} for the given purl
# types, consumed by the shared jq program via --argjson. Ecosystem strings are
# simple ASCII (no quotes/backslashes) so hand-building the JSON is safe.
feed_build_ecomap() {
    local out="{" first=1 t eco
    for t in "$@"; do
        [ -z "$t" ] && continue
        eco=$(feed_eco_string "$t")
        [ -z "$eco" ] && continue
        [ "$first" -eq 0 ] && out="$out,"
        out="$out\"$eco\":\"$t\""
        first=0
    done
    printf '%s}' "$out"
}

# Shared jq program. Emits one PURL line per affected package/range for every
# ecosystem present in $ecomap. Reproduces the legacy npm emission byte-for-byte
# (npm's transform is identity and $ecomap={"npm":"npm"} matches the old filter),
# while adding per-type name canonicalization that MUST match canon_purl_name in
# the scan-side parser (src/31-parsers-purl.sh):
#   pypi           -> lowercase, collapse runs of [-_.] to a single '-'
#   maven          -> groupId:artifactId emitted as groupId/artifactId
#   composer/nuget/githubactions -> lowercase
#   swift          -> strip http(s):// scheme and trailing .git, lowercase
#   npm/golang/cargo/gem/pub/hex -> name as-is
# $source is "ghsa" or "osv" and controls the GHSA-id extraction + source= param.
FEED_JQ_PROGRAM='
def emit_name($type; $name):
    if $type == "pypi" then ($name | ascii_downcase | gsub("[-_.]+"; "-"))
    elif $type == "maven" then ($name | gsub(":"; "/"))
    elif ($type == "composer" or $type == "nuget" or $type == "githubactions") then ($name | ascii_downcase)
    elif $type == "swift" then ($name | sub("^https?://"; "") | sub("\\.git$"; "") | ascii_downcase)
    else $name end;

.id as $id |
(.database_specific.severity //
 (.severity[]? | select(.type == "CVSS_V3" or .type == "CVSS_V2") | .score |
  if . then
    (. | capture("CVSS:[^/]+/[^/]+/(?<score>[0-9.]+)") | .score | tonumber |
     if . >= 9.0 then "CRITICAL"
     elif . >= 7.0 then "HIGH"
     elif . >= 4.0 then "MODERATE"
     else "LOW" end)
  else null end) //
 "UNKNOWN") as $severity |

(.aliases // []) as $aliases |
(if $source == "ghsa" then
    (if ($id | startswith("GHSA-")) then $id else "" end)
 else
    ($aliases | map(select(startswith("GHSA-"))) | .[0] // "")
 end) as $ghsa |
($aliases | map(select(startswith("CVE-"))) | .[0] // "") as $cve |

.affected[]? |
.package.ecosystem as $e |
($ecomap[$e] // "") as $type |
select($type != "") |
(emit_name($type; .package.name)) as $pkg |
(
    (.ranges[]? |
        select(.type == "SEMVER" or .type == "ECOSYSTEM") |
        .events |
        map(select(.introduced or .fixed or .last_affected)) |
        if length > 0 then
            reduce .[] as $event (
                {introduced: null, fixed: null, last_affected: null};
                if $event.introduced then
                    .introduced = $event.introduced
                elif $event.fixed then
                    .fixed = $event.fixed
                elif $event.last_affected then
                    .last_affected = $event.last_affected
                else . end
            ) |
            ([
                ("severity=" + ($severity | ascii_downcase)),
                (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                (if $cve != "" then "cve=" + $cve else empty end),
                ("source=" + $source)
            ] | join("&")) as $params |

            if .introduced and .fixed then
                "pkg:\($type)/\($pkg)@>=\(.introduced) <\(.fixed)?\($params)"
            elif .introduced and .last_affected then
                "pkg:\($type)/\($pkg)@>=\(.introduced) <=\(.last_affected)?\($params)"
            elif .introduced then
                "pkg:\($type)/\($pkg)@>=\(.introduced)?\($params)"
            elif .fixed then
                "pkg:\($type)/\($pkg)@<\(.fixed)?\($params)"
            elif .last_affected then
                "pkg:\($type)/\($pkg)@<=\(.last_affected)?\($params)"
            else empty end
        else empty end
    ),
    # Output exact versions for entries without SEMVER/ECOSYSTEM ranges (e.g., MAL advisories)
    (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
        ([
            ("severity=" + ($severity | ascii_downcase)),
            (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
            (if $cve != "" then "cve=" + $cve else empty end),
            ("source=" + $source)
        ] | join("&")) as $params |
        .versions[]? |
        "pkg:\($type)/\($pkg)@\(.)?\($params)"
    else empty end)
)
'

# Run FEED_JQ_PROGRAM over every *.json file under an input directory, in
# parallel, and append the raw (unsorted) PURL lines to a combined file.
#   $1 input dir   $2 source ("ghsa"|"osv")   $3 ecomap JSON   $4 combined out
#
# Robustness: 8 parallel workers each write to their OWN temp file — never a
# shared pipe — because concurrent jq processes writing to one pipe interleave
# non-atomically and tear PURL lines (observed frequently under load). Each
# worker runs jq once per file (error isolation for the rare malformed
# advisory), so a single bad JSON never drops its whole chunk. This keeps the
# "xargs -P 8 parallel jq" design while producing deterministic, uncorrupted
# feeds. Callers sort/split the combined file (LC_ALL=C for locale stability).
feed_emit_raw() {
    local in_dir="$1" src="$2" ecomap="$3" combined="$4"
    local parts_dir
    parts_dir=$(mktemp -d)
    export FEED_JQ_PROGRAM
    find "$in_dir" -name "*.json" -type f -print0 | \
        FEED_SRC="$src" FEED_ECOMAP="$ecomap" PARTS_DIR="$parts_dir" \
        xargs -0 -P 8 -n 400 sh -c '
            out=$(mktemp "$PARTS_DIR/part.XXXXXX") || exit 1
            for f in "$@"; do
                jq -r --arg source "$FEED_SRC" --argjson ecomap "$FEED_ECOMAP" "$FEED_JQ_PROGRAM" "$f" 2>/dev/null
            done > "$out"
        ' _ 2>/dev/null || true
    cat "$parts_dir"/part.* > "$combined" 2>/dev/null || true
    rm -rf "$parts_dir"
}

# Fetch GitHub Security Advisory data for the requested ecosystems.
# Usage: fetch_ghsa [purl-type ...]   (default: all supported types)
# Writes data/ghsa.purl (npm, legacy name) and data/ghsa-<type>.purl (others)
# into ${FEED_OUTPUT_DIR:-data}. Performs a SINGLE sparse clone and a SINGLE
# parallel jq pass over the advisory files, then splits the combined output by
# pkg:<type>/ prefix — never cloning or scanning per ecosystem.
fetch_ghsa() {
    local -a types=("$@")
    if [ "${#types[@]}" -eq 0 ]; then
        read -ra types <<< "$(feed_all_types)"
    fi

    local out_dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)

    # Keep only supported types (warn + drop unknowns).
    local -a valid_types=()
    local t
    for t in "${types[@]}"; do
        [ -z "$t" ] && continue
        if [ -z "$(feed_eco_string "$t")" ]; then
            echo "⚠️  Skipping unknown ecosystem: $t" >&2
            continue
        fi
        valid_types+=("$t")
    done
    [ "${#valid_types[@]}" -eq 0 ] && return 0

    local ecomap
    ecomap=$(feed_build_ecomap "${valid_types[@]}")

    local ghsa_tmp
    ghsa_tmp=$(mktemp -d)
    local GHSA_REPO="https://github.com/github/advisory-database.git"
    local CLONE_DIR="$ghsa_tmp/advisory-database"

    echo "Cloning GitHub Advisory Database (all reviewed advisories)..." >&2

    # Shallow clone with sparse checkout for all reviewed advisories
    git clone --filter=blob:none --no-checkout --depth 1 "$GHSA_REPO" "$CLONE_DIR" 2>&1 | grep -v "^remote:" | grep -v "^Cloning" | grep -v "^$" || true
    (
        cd "$CLONE_DIR" || exit 1
        git sparse-checkout init --cone 2>&1 | grep -v "^$" || true
        git sparse-checkout set advisories/github-reviewed 2>&1 | grep -v "^$" || true
        git checkout 2>&1 | grep -v "^remote:" | grep -v "^Your branch" | grep -v "^$" || true
    ) || true

    echo "Processing GHSA advisories for: ${valid_types[*]}" >&2

    local file_count
    file_count=$(find "$CLONE_DIR/advisories/github-reviewed" -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count advisory files" >&2
    echo "Using parallel processing (single pass, all ecosystems)..." >&2

    # SINGLE parallel jq pass emitting PURLs for every requested ecosystem.
    local combined="$ghsa_tmp/combined.purl"
    feed_emit_raw "$CLONE_DIR/advisories/github-reviewed" "ghsa" "$ecomap" "$combined"

    # Split combined output by pkg:<type>/ prefix into per-ecosystem files.
    local base out_file line_count
    for t in "${valid_types[@]}"; do
        base=$(default_feed_filename "ghsa" "$t")
        out_file="$out_dir/$base"
        # LC_ALL=C: deterministic byte-order sort, reproducible across locales
        # (matches the CI runner and keeps committed feed diffs to real churn).
        { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u > "$out_file"
        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2
    done

    rm -rf "$ghsa_tmp"
    echo "GHSA processing complete" >&2
}

# Fetch OSV vulnerability data for the requested ecosystems.
# Usage: fetch_osv [purl-type ...]   (default: all supported types)
# Writes data/osv.purl (npm, legacy name) and data/osv-<type>.purl (others)
# into ${FEED_OUTPUT_DIR:-data}. Downloads one all.zip per ecosystem and reuses
# the shared jq emission via the existing xargs -P 8 parallel pattern.
fetch_osv() {
    local -a types=("$@")
    if [ "${#types[@]}" -eq 0 ]; then
        read -ra types <<< "$(feed_all_types)"
    fi

    local out_dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)

    local t eco_string osv_dir ecomap zip_file eco_tmp out_file base file_count line_count
    for t in "${types[@]}"; do
        [ -z "$t" ] && continue
        eco_string=$(feed_eco_string "$t")
        if [ -z "$eco_string" ]; then
            echo "⚠️  Skipping unknown ecosystem: $t" >&2
            continue
        fi
        osv_dir=$(feed_osv_dir "$t")
        ecomap=$(feed_build_ecomap "$t")
        base=$(default_feed_filename "osv" "$t")
        out_file="$out_dir/$base"

        eco_tmp=$(mktemp -d)
        zip_file="$eco_tmp/all.zip"

        echo "Fetching OSV $eco_string vulnerabilities..." >&2
        if ! curl -sL "https://osv-vulnerabilities.storage.googleapis.com/${osv_dir}/all.zip" -o "$zip_file"; then
            echo "⚠️  Failed to download OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            continue
        fi

        echo "Extracting $eco_string vulnerabilities..." >&2
        if ! unzip -q "$zip_file" -d "$eco_tmp" 2>/dev/null; then
            echo "⚠️  Failed to extract OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            continue
        fi

        file_count=$(find "$eco_tmp" -name "*.json" -type f | wc -l | tr -d ' ')
        echo "Processing $file_count $eco_string files (parallel)..." >&2

        # Robust parallel emission, then deterministic C-locale sort/dedupe.
        local combined="$eco_tmp/combined.purl"
        feed_emit_raw "$eco_tmp" "osv" "$ecomap" "$combined"
        LC_ALL=C sort -u "$combined" > "$out_file" || true

        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2

        rm -rf "$eco_tmp"
    done

    echo "OSV processing complete" >&2
}

# Main orchestration function to fetch all PURL vulnerability feeds
# (GHSA + OSV) for every supported ecosystem.
fetch_all() {
    local output_dir="${1:-data}"

    echo "========================================="
    echo "Vulnerability PURL Feed Generator"
    echo "========================================="
    echo ""

    mkdir -p "$output_dir"

    export FEED_OUTPUT_DIR="$output_dir"

    # Generate OSV feeds (one zip per ecosystem)
    echo "Generating OSV feeds for all ecosystems..."
    fetch_osv
    echo ""

    # Generate GHSA feeds (single clone, single pass, split per ecosystem)
    echo "Generating GHSA feeds for all ecosystems..."
    fetch_ghsa
    echo ""

    unset FEED_OUTPUT_DIR

    echo "========================================="
    echo "Feed generation complete!"
    echo "========================================="
    echo "Per-ecosystem totals:"
    local f count total=0
    for f in "$output_dir"/*.purl; do
        [ -e "$f" ] || continue
        count=$(wc -l < "$f" | tr -d ' ')
        total=$((total + count))
        printf '  - %-24s %s\n' "$(basename "$f")" "$count"
    done
    echo "  ---------------------------------------"
    printf '  - %-24s %s\n' "TOTAL" "$total"
    echo ""
}

# Find default source file with fallback logic
# Tries multiple locations in order:
# 1. Homebrew installation path
# 2. Local ./data/ directory
# 3. Docker /app/data/ directory
# 4. Remote GitHub URL
# Returns path/URL if found, empty string if not found
find_default_source() {
    local source_file="$1"  # e.g., "ghsa.purl" or "osv.purl"

    # Try Homebrew path
    if command -v brew &> /dev/null; then
        local brew_path="$(brew --prefix)/share/package-checker/data/$source_file"
        if [ -f "$brew_path" ]; then
            echo "$brew_path"
            return 0
        fi
    fi

    # Try local ./data/ directory
    if [ -f "./data/$source_file" ]; then
        echo "./data/$source_file"
        return 0
    fi

    # Try Docker /app/data/ directory
    if [ -f "/app/data/$source_file" ]; then
        echo "/app/data/$source_file"
        return 0
    fi

    # Try remote GitHub URL as last resort
    local github_url="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/$source_file"
    if curl --output /dev/null --silent --head --fail "$github_url" 2>/dev/null; then
        echo "$github_url"
        return 0
    fi

    # Nothing found
    echo ""
    return 1
}

# Main execution
