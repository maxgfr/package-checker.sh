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
#   composer/nuget -> lowercase
#   githubactions  -> strip any scheme and "github.com/", lowercase
#   swift          -> strip any scheme, trailing "/" and ".git", lowercase
#   npm/golang/cargo/gem/pub/hex -> name as-is
# $source is "ghsa" or "osv" (the source= param). Severity: the advisory's own
# (GHSA database_specific), else the CVSS 3.x base score computed from the
# first CVSS_V3 vector, MAL- (malicious package) advisories being critical.
FEED_JQ_PROGRAM='
def emit_name($type; $name):
    if $type == "pypi" then ($name | ascii_downcase | gsub("[-_.]+"; "-"))
    elif $type == "maven" then ($name | gsub(":"; "/"))
    elif ($type == "composer" or $type == "nuget") then ($name | ascii_downcase)
    elif $type == "githubactions" then ($name | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | sub("^github\\.com/"; "") | sub("/+$"; "") | ascii_downcase)
    elif $type == "swift" then ($name | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | sub("/+$"; "") | sub("\\.git$"; "") | ascii_downcase)
    else $name end;

# CVSS 3.x base score of a vector ("CVSS:3.1/AV:N/AC:L/..."), null when the
# vector is not a complete 3.x one. Roundup as defined by CVSS 3.1.
def roundup: ((. * 100000) | round) as $i
    | if ($i % 10000) == 0 then $i / 100000 else (($i / 10000 | floor) + 1) / 10 end;
def cvss3_score:
    if (type == "string" and test("^CVSS:3\\.[01]/")) then
        # A missing metric reads as "" so the lookups give null, never an error.
        ((split("/")[1:] | map(split(":") | {(.[0]): (.[1] // "")}) | add) // {}) as $m
        | ($m.S == "C") as $changed
        | ({"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[$m.AV // ""]) as $av
        | ({"L": 0.77, "H": 0.44}[$m.AC // ""]) as $ac
        | (if $changed then {"N": 0.85, "L": 0.68, "H": 0.5} else {"N": 0.85, "L": 0.62, "H": 0.27} end)[$m.PR // ""] as $pr
        | ({"N": 0.85, "R": 0.62}[$m.UI // ""]) as $ui
        | ([$m.C, $m.I, $m.A] | map({"H": 0.56, "L": 0.22, "N": 0}[. // ""])) as $cia
        | if ([$av, $ac, $pr, $ui] + $cia | any(. == null)) then null else
            (1 - ((1 - $cia[0]) * (1 - $cia[1]) * (1 - $cia[2]))) as $iss
            | (if $changed then 7.52 * ($iss - 0.029) - 3.25 * pow($iss - 0.02; 15) else 6.42 * $iss end) as $impact
            | (8.22 * $av * $ac * $pr * $ui) as $exploit
            | if $impact <= 0 then 0
              elif $changed then ([1.08 * ($impact + $exploit), 10] | min | roundup)
              else ([$impact + $exploit, 10] | min | roundup) end
          end
    elif (type == "string" and test("^[0-9]+(\\.[0-9]+)?$")) then tonumber
    else null end;
def score_severity:
    if . >= 9.0 then "CRITICAL"
    elif . >= 7.0 then "HIGH"
    elif . >= 4.0 then "MODERATE"
    elif . > 0 then "LOW"
    else null end;

select(.withdrawn == null) |
.id as $id |
(if ($id | startswith("MAL-")) then "CRITICAL"
 else (.database_specific.severity //
       first(.severity[]? | select(.type == "CVSS_V3") | .score | cvss3_score | numbers | score_severity | strings) //
       "UNKNOWN") end) as $severity |

(.aliases // []) as $aliases |
# The GHSA id is the advisory id itself (GHSA feed, and OSV copies of GHSA
# advisories) or else a GHSA alias. Any other non-CVE id (PYSEC-, GO-,
# RUSTSEC-, MAL-, ...) is kept as id=.
(if ($id | startswith("GHSA-")) then $id
 else ($aliases | map(select(startswith("GHSA-"))) | .[0] // "") end) as $ghsa |
(if ($id | startswith("CVE-")) then $id
 else ($aliases | map(select(startswith("CVE-"))) | .[0] // "") end) as $cve |
(if ($id | startswith("GHSA-") or startswith("CVE-")) then "" else $id end) as $other_id |
([
    ("severity=" + ($severity | ascii_downcase)),
    (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
    (if $cve != "" then "cve=" + $cve else empty end),
    (if $other_id != "" then "id=" + $other_id else empty end),
    ("source=" + $source)
] | join("&")) as $params |

.affected[]? |
.package.ecosystem as $e |
($ecomap[$e // ""] // "") as $type |
select($type != "") |
(emit_name($type; .package.name)) as $pkg |
# GHSA records the upper bound of an interval with no known fix here
# ("< 3.0.0", "<= 2.26.11"): it bounds the open interval, but is no fix.
((.database_specific.last_known_affected_version_range // "") | gsub(" "; "")
 | if test("^<=?[0-9A-Za-z]") then . else "" end) as $last_known |
(
    (.ranges[]? |
        select(.type == "SEMVER" or .type == "ECOSYSTEM") |
        .events |
        ([.[] | select(.limit) | .limit] | if length == 0 then ["*"] else . end) as $limits |
        map(select(.introduced or .fixed or .last_affected)) |
        if length > 0 then
            reduce .[] as $event (
                {current: {}, intervals: []};
                if $event.introduced then
                    .current = {introduced: $event.introduced}
                elif $event.fixed then
                    .intervals += [(.current + {fixed: $event.fixed})] |
                    .current = {}
                elif $event.last_affected then
                    .intervals += [(.current + {last_affected: $event.last_affected})] |
                    .current = {}
                else . end
            ) |
            (.intervals + (if .current.introduced then [.current] else [] end))[] |
            . as $interval |
            ($interval.fixed == null and $interval.last_affected == null and $last_known != "") as $bounded |
            ([
                (if .introduced then ">=" + .introduced else empty end),
                (if .fixed then "<" + .fixed else empty end),
                (if .last_affected then "<=" + .last_affected else empty end),
                (if $bounded then $last_known else empty end)
            ] | join(" ")) as $bounds |
            $limits[] as $limit |
            (if $limit == "*" then "" else " <" + $limit end) as $cap |
            # A limit or a last-known bound is an applicability boundary, not a
            # known patched version.
            (if ($limit != "*" or $bounded) and ($interval.fixed == null) then "&fixed=" else "" end) as $fix_override |
            "pkg:\($type)/\($pkg)@\($bounds)\($cap)?\($params)\($fix_override)"
        else empty end
    ),
    # Exact versions only for entries without SEMVER/ECOSYSTEM ranges (e.g. MAL
    # advisories): OSV enumerates every version a range covers, so emitting them
    # alongside ranges is redundant and pushes feeds past the GitHub 100 MB file limit.
    (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
        .versions[]? |
        "pkg:\($type)/\($pkg)@\(.)?\($params)"
    else empty end)
)'

# Run FEED_JQ_PROGRAM over every *.json file under an input directory, in
# parallel, and append the raw (unsorted) PURL lines to a combined file.
#   $1 input dir   $2 source ("ghsa"|"osv")   $3 ecomap JSON   $4 combined out
#
# Robustness: 8 parallel workers each write to their OWN temp file — never a
# shared pipe — because concurrent jq processes writing to one pipe interleave
# non-atomically and tear PURL lines (observed frequently under load). Each
# worker runs jq once per file, so a malformed advisory is isolated: it is
# skipped and counted (its partial output discarded) instead of failing the
# whole ecosystem. Only a failed worker, or every file failing, prevents
# replacement of the existing feed. Callers sort/split the combined file
# (LC_ALL=C for locale stability).
feed_emit_raw() {
    local in_dir="$1" src="$2" ecomap="$3" combined="$4"
    [ -d "$in_dir" ] && command -v jq >/dev/null 2>&1 || return 1
    local parts_dir total skipped
    parts_dir=$(mktemp -d)
    export FEED_JQ_PROGRAM
    if ! (set -o pipefail; find "$in_dir" -name "*.json" -type f -print0 | \
        FEED_SRC="$src" FEED_ECOMAP="$ecomap" PARTS_DIR="$parts_dir" \
        xargs -0 -P 8 -n 400 sh -c '
            out=$(mktemp "$PARTS_DIR/part.XXXXXX") || exit 1
            bad=$(mktemp "$PARTS_DIR/bad.XXXXXX") || exit 1
            for f in "$@"; do
                if lines=$(jq -r --arg source "$FEED_SRC" --argjson ecomap "$FEED_ECOMAP" "$FEED_JQ_PROGRAM" "$f" 2>/dev/null); then
                    [ -z "$lines" ] || printf "%s\n" "$lines"
                else
                    printf "%s\n" "$f" >> "$bad"
                fi
            done > "$out"
        ' _ 2>/dev/null); then
        echo "Error: Failed to generate feed; previous output preserved" >&2
        rm -rf "$parts_dir"
        return 1
    fi
    total=$(find "$in_dir" -name "*.json" -type f | wc -l | tr -d ' ')
    skipped=$(cat "$parts_dir"/bad.* 2>/dev/null | wc -l | tr -d ' ')
    if [ "$skipped" -gt 0 ]; then
        echo "⚠️  Skipped $skipped of $total advisory file(s) that jq could not process" >&2
        if [ "$skipped" -ge "$total" ]; then
            echo "Error: no advisory could be processed; previous output preserved" >&2
            rm -rf "$parts_dir"
            return 1
        fi
    fi
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
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
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
    if ! git clone --filter=blob:none --no-checkout --depth 1 "$GHSA_REPO" "$CLONE_DIR" > "$ghsa_tmp/clone.log" 2>&1 || ! (
        cd "$CLONE_DIR" || exit 1
        git sparse-checkout init --cone &&
        git sparse-checkout set advisories/github-reviewed &&
        git checkout
    ) > "$ghsa_tmp/checkout.log" 2>&1; then
        echo "Error: Failed to fetch GHSA database; previous feeds preserved" >&2
        rm -rf "$ghsa_tmp"
        return 1
    fi

    echo "Processing GHSA advisories for: ${valid_types[*]}" >&2

    local file_count
    file_count=$(find "$CLONE_DIR/advisories/github-reviewed" -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count advisory files" >&2
    echo "Using parallel processing (single pass, all ecosystems)..." >&2

    # SINGLE parallel jq pass emitting PURLs for every requested ecosystem.
    local combined="$ghsa_tmp/combined.purl"
    if ! feed_emit_raw "$CLONE_DIR/advisories/github-reviewed" "ghsa" "$ecomap" "$combined"; then
        rm -rf "$ghsa_tmp"
        return 1
    fi

    # Split combined output by pkg:<type>/ prefix into per-ecosystem files.
    local base out_file line_count
    for t in "${valid_types[@]}"; do
        base=$(default_feed_filename "ghsa" "$t")
        out_file="$out_dir/$base"
        # LC_ALL=C: deterministic byte-order sort, reproducible across locales
        # (matches the CI runner and keeps committed feed diffs to real churn).
        local staged
        staged=$(mktemp "$out_file.tmp.XXXXXX") || return 1
        if ! { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u > "$staged" || ! mv "$staged" "$out_file"; then
            rm -f "$staged"
            rm -rf "$ghsa_tmp"
            return 1
        fi
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
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
    local failed=0
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
        if ! curl -fsSL --connect-timeout 10 --max-time 300 "https://osv-vulnerabilities.storage.googleapis.com/${osv_dir}/all.zip" -o "$zip_file"; then
            echo "⚠️  Failed to download OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        echo "Extracting $eco_string vulnerabilities..." >&2
        if ! unzip -q "$zip_file" -d "$eco_tmp" 2>/dev/null; then
            echo "⚠️  Failed to extract OSV feed for $t; skipping" >&2
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        file_count=$(find "$eco_tmp" -name "*.json" -type f | wc -l | tr -d ' ')
        echo "Processing $file_count $eco_string files (parallel)..." >&2

        # Robust parallel emission, then deterministic C-locale sort/dedupe.
        local combined="$eco_tmp/combined.purl"
        local staged
        if ! feed_emit_raw "$eco_tmp" "osv" "$ecomap" "$combined"; then
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi
        staged=$(mktemp "$out_file.tmp.XXXXXX") || return 1
        if ! LC_ALL=C sort -u "$combined" > "$staged" || ! mv "$staged" "$out_file"; then
            rm -f "$staged"
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        line_count=$(wc -l < "$out_file" | tr -d ' ')
        echo "  → $base: $line_count entries" >&2

        rm -rf "$eco_tmp"
    done

    echo "OSV processing complete" >&2
    return "$failed"
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

    # An OSV failure must not prevent the GHSA feeds: run both, report both.
    local status=0

    # Generate OSV feeds (one zip per ecosystem)
    echo "Generating OSV feeds for all ecosystems..."
    fetch_osv || status=1
    echo ""

    # Generate GHSA feeds (single clone, single pass, split per ecosystem)
    echo "Generating GHSA feeds for all ecosystems..."
    fetch_ghsa || status=1
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
    [ "$status" -eq 0 ] || echo "⚠️  Some feeds could not be generated; previous files were kept" >&2
    return "$status"
}

# Find default source file with fallback logic. Tries, in order:
# 1. the data/ directory next to this script (a git checkout or release)
# 2. the Homebrew installation path
# 3. the Docker /app/data/ directory
# 4. ./data/ in the current directory
# 5. the remote GitHub URL
# The scanned project's own ./data must not shadow the built-in feeds, so the
# current directory comes after every installation path.
# Returns path/URL if found, empty string if not found
find_default_source() {
    local source_file="$1"  # e.g., "ghsa.purl" or "osv.purl"

    local script_dir=""
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || script_dir=""
    fi
    if [ -n "$script_dir" ] && [ -f "$script_dir/data/$source_file" ]; then
        echo "$script_dir/data/$source_file"
        return 0
    fi

    # Try Homebrew path
    if command -v brew &> /dev/null; then
        local brew_path
        brew_path="$(brew --prefix)/share/package-checker/data/$source_file"
        if [ -f "$brew_path" ]; then
            echo "$brew_path"
            return 0
        fi
    fi

    # Try Docker /app/data/ directory
    if [ -f "/app/data/$source_file" ]; then
        echo "/app/data/$source_file"
        return 0
    fi

    # Try local ./data/ directory
    if [ -f "./data/$source_file" ]; then
        echo "./data/$source_file"
        return 0
    fi

    # Try remote GitHub URL as last resort
    local github_url="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/$source_file"
    if curl --output /dev/null --silent --head --fail --connect-timeout 10 --max-time 30 "$github_url" 2>/dev/null; then
        echo "$github_url"
        return 0
    fi

    # Nothing found
    echo ""
    return 1
}

# Main execution
