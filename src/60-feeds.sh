# ============================================================================
# Vulnerability Feed Generation Functions
# ============================================================================
#
# Feeds are generated from two upstream sources, both using the OSV schema:
#   - GHSA:  a single sparse clone of github/advisory-database, scanned once,
#            emitting PURL lines for every supported ecosystem at once.
#   - OSV:   one all.zip per ecosystem from the OSV GCS bucket.
#   - Runtime: the Node.js / PHP advisories of the OSV "Bitnami" ecosystem
#            (fetch_runtime), checked against the runtime a project targets.
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
# shellcheck disable=SC2089,SC2090 # a jq program, passed through the environment
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
        | ({"U": false, "C": true}[$m.S // ""]) as $changed
        | ({"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[$m.AV // ""]) as $av
        | ({"L": 0.77, "H": 0.44}[$m.AC // ""]) as $ac
        | (if $changed then {"N": 0.85, "L": 0.68, "H": 0.5} else {"N": 0.85, "L": 0.62, "H": 0.27} end)[$m.PR // ""] as $pr
        | ({"N": 0.85, "R": 0.62}[$m.UI // ""]) as $ui
        | ([$m.C, $m.I, $m.A] | map({"H": 0.56, "L": 0.22, "N": 0}[. // ""])) as $cia
        | if ([$av, $ac, $pr, $ui, $changed] + $cia | any(. == null)) then null else
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

# Every field is read through a type guard: one malformed value must not
# make jq fail, which would drop every package of the advisory file.
select(type == "object" and .withdrawn == null) |
(.id | strings // "") as $id |
(if ($id | startswith("MAL-")) then "CRITICAL"
 else ((.database_specific | objects | .severity | strings) //
       first(.severity[]? | objects | select(.type == "CVSS_V3") | .score | cvss3_score | numbers | score_severity | strings) //
       "UNKNOWN") end) as $severity |

[.aliases[]? | strings] as $aliases |
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

.affected[]? | objects |
((.package | objects | .ecosystem | strings) // "") as $e |
($ecomap[$e] // "") as $type |
select($type != "") |
((.package.name | strings) // "") as $name |
select($name != "") |
# RustSec informational notices "unmaintained" and "notice" are warnings
# about a crate, not vulnerabilities of its versions (cargo audit reports them
# apart): listing them would flag every version as vulnerable. "unsound"
# notices describe a defect of specific versions and are kept.
select(((.database_specific | objects | .informational) // null) as $info
       | $info == null or $info == "unsound") |
(emit_name($type; $name)) as $pkg |
# GHSA records the upper bound of an interval with no known fix here
# ("< 3.0.0", "<= 2.26.11"): it bounds the open interval, but is no fix.
((.database_specific | objects | .last_known_affected_version_range | strings) // "" | gsub(" "; "")
 | if test("^<=?[0-9A-Za-z]") then . else "" end) as $last_known |
# Ranges that define an interval (a range with only "limit" events does not).
[.ranges[]? | objects | select(.type == "SEMVER" or .type == "ECOSYSTEM")
 | select([.events[]? | objects | select(.introduced or .fixed or .last_affected)] | length > 0)] as $ranges |
(
    ($ranges[] |
        [.events[]? | objects] |
        ([.[] | select(.limit) | .limit | strings] | if length == 0 then ["*"] else . end) as $limits |
        map(select(.introduced or .fixed or .last_affected)) |
        if length > 0 then
            reduce .[] as $event (
                {current: {}, intervals: []};
                if $event.introduced then
                    # A second "introduced" inside an open interval changes
                    # nothing: the versions since the first one stay affected.
                    if .current.introduced then . else .current = {introduced: $event.introduced} end
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
    # Exact versions only for entries without a SEMVER/ECOSYSTEM interval (e.g.
    # MAL advisories, or ranges with only "limit" events): OSV enumerates every
    # version a range covers, so emitting them alongside ranges is redundant and
    # pushes feeds past the GitHub 100 MB file limit.
    (if ($ranges | length) == 0 then
        .versions[]? | strings | select(. != "") |
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
# worker runs jq once per batch of 400 files (one process start instead of
# 400); a batch that jq cannot process is redone file by file, so a malformed
# advisory is isolated: it is skipped and counted (its partial output
# discarded) instead of failing the whole ecosystem. A failed write, a failed
# worker, no input file, or every file failing prevents replacement of the
# existing feed. Callers sort/split the combined file (LC_ALL=C for locale
# stability).
feed_emit_raw() {
    local in_dir="$1" src="$2" ecomap="$3" combined="$4"
    [ -d "$in_dir" ] && command -v jq >/dev/null 2>&1 || return 1
    local parts_dir total skipped
    total=$(find "$in_dir" -name "*.json" -type f | wc -l | tr -d ' ')
    if [ "$total" -eq 0 ]; then
        echo "Error: no advisory file found in $in_dir; previous output preserved" >&2
        return 1
    fi
    parts_dir=$(mktemp -d) || return 1
    # shellcheck disable=SC2090
    export FEED_JQ_PROGRAM
    if ! (set -o pipefail; find "$in_dir" -name "*.json" -type f -print0 | \
        FEED_SRC="$src" FEED_ECOMAP="$ecomap" PARTS_DIR="$parts_dir" \
        xargs -0 -P 8 -n 400 sh -c '
            out=$(mktemp "$PARTS_DIR/part.XXXXXX") || exit 1
            bad=$(mktemp "$PARTS_DIR/bad.XXXXXX") || exit 1
            emit() { jq -r --arg source "$FEED_SRC" --argjson ecomap "$FEED_ECOMAP" "$FEED_JQ_PROGRAM" "$@" 2>/dev/null; }
            if ! emit "$@" > "$out"; then
                : > "$out" || exit 1
                for f in "$@"; do
                    if lines=$(emit "$f"); then
                        if [ -n "$lines" ]; then printf "%s\n" "$lines" >> "$out" || exit 1; fi
                    else
                        printf "%s\n" "$f" >> "$bad" || exit 1
                    fi
                done
            fi
        ' _); then
        echo "Error: Failed to generate feed; previous output preserved" >&2
        rm -rf "$parts_dir"
        return 1
    fi
    skipped=$(cat "$parts_dir"/bad.* 2>/dev/null | wc -l | tr -d ' ')
    if [ "$skipped" -gt 0 ]; then
        echo "⚠️  Skipped $skipped of $total advisory file(s) that jq could not process" >&2
        if [ "$skipped" -ge "$total" ]; then
            echo "Error: no advisory could be processed; previous output preserved" >&2
            rm -rf "$parts_dir"
            return 1
        fi
    fi
    if ! cat "$parts_dir"/part.* > "$combined"; then
        echo "Error: unable to write $combined; previous output preserved" >&2
        rm -rf "$parts_dir"
        return 1
    fi
    rm -rf "$parts_dir"
}

# First line of a generated feed: "# generated: <UTC ISO 8601>", the same
# for every feed of one run (see feed_file_meta).
feed_generated_header() {
    if [ -z "${FEED_GENERATED_AT:-}" ]; then
        feed_clock
        epoch_to_iso "$NOW_EPOCH"
        FEED_GENERATED_AT="$EPOCH_ISO"
    fi
    printf '# generated: %s\n' "$FEED_GENERATED_AT"
}

# Replace a feed file with a staged one, atomically, only when the staged file
# holds advisories: an empty result means a broken download or parse, not a
# feed with no advisory. Feed files are world-readable like committed ones (mktemp
# creates them 0600). Returns non-zero when the previous file was kept.
feed_install() {
    local staged="$1" out_file="$2"
    # Only purl lines, comments and blank lines: an HTML page (proxy block
    # page, captive portal) served with 200 is not a feed.
    if grep -qvE '^(pkg:|#|$)' "$staged"; then
        echo "⚠️  ${out_file##*/} is not a purl feed; previous file preserved" >&2
        rm -f "$staged"
        return 1
    fi
    if ! grep -q '^pkg:' "$staged"; then
        echo "⚠️  No entry for ${out_file##*/}; previous file preserved" >&2
        rm -f "$staged"
        return 1
    fi
    chmod 644 "$staged" && mv "$staged" "$out_file" && return 0
    rm -f "$staged"
    return 1
}

# Purl types requested on the command line (--fetch-ghsa / --fetch-osv):
# lockfile aliases (go, rust, python...) map to their purl type. Sets
# FEED_TYPES; returns non-zero, after an error message, when a token is not
# a supported ecosystem.
feed_resolve_types() {
    FEED_TYPES=()
    local token type
    for token in "$@"; do
        [ -n "$token" ] || continue
        type=$(ecosystem_alias_to_purl "$token")
        if [ -z "$(feed_eco_string "$type")" ]; then
            echo "Error: unknown ecosystem '$token' (supported: $(feed_all_types))" >&2
            return 1
        fi
        case " ${FEED_TYPES[*]} " in *" $type "*) ;; *) FEED_TYPES+=("$type") ;; esac
    done
}

# Create (if needed) and print the absolute feed output directory.
feed_output_dir() {
    local dir="${FEED_OUTPUT_DIR:-data}"
    mkdir -p "$dir" && (cd "$dir" && pwd)
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

    feed_resolve_types "${types[@]}" || return 1
    local -a valid_types=("${FEED_TYPES[@]}")
    if [ "${#valid_types[@]}" -eq 0 ]; then
        echo "Error: no ecosystem to fetch" >&2
        return 1
    fi

    local out_dir
    out_dir=$(feed_output_dir) || { echo "Error: unable to create the feed directory" >&2; return 1; }

    local ecomap t
    ecomap=$(feed_build_ecomap "${valid_types[@]}")

    local ghsa_tmp
    ghsa_tmp=$(mktemp -d) || return 1
    register_temp_dir "$ghsa_tmp"
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
    local base out_file line_count staged failed=0
    for t in "${valid_types[@]}"; do
        base=$(default_feed_filename "ghsa" "$t")
        out_file="$out_dir/$base"
        # LC_ALL=C: deterministic byte-order sort, reproducible across locales
        # (matches the CI runner and keeps committed feed diffs to real churn).
        if ! staged=$(mktemp "$out_file.tmp.XXXXXX"); then
            failed=1
            continue
        fi
        if ! { feed_generated_header && { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u; } > "$staged" ||
            ! feed_install "$staged" "$out_file"; then
            rm -f "$staged"
            failed=1
            continue
        fi
        line_count=$(grep -c '^pkg:' "$out_file")
        echo "  → $base: $line_count entries" >&2
    done

    rm -rf "$ghsa_tmp"
    echo "GHSA processing complete" >&2
    return "$failed"
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

    feed_resolve_types "${types[@]}" || return 1
    types=("${FEED_TYPES[@]}")
    if [ "${#types[@]}" -eq 0 ]; then
        echo "Error: no ecosystem to fetch" >&2
        return 1
    fi

    local out_dir
    out_dir=$(feed_output_dir) || { echo "Error: unable to create the feed directory" >&2; return 1; }

    local t eco_string osv_dir ecomap zip_file eco_tmp out_file base file_count line_count
    for t in "${types[@]}"; do
        eco_string=$(feed_eco_string "$t")
        osv_dir=$(feed_osv_dir "$t")
        ecomap=$(feed_build_ecomap "$t")
        base=$(default_feed_filename "osv" "$t")
        out_file="$out_dir/$base"

        if ! eco_tmp=$(mktemp -d); then
            failed=1
            continue
        fi
        register_temp_dir "$eco_tmp"
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
        if ! staged=$(mktemp "$out_file.tmp.XXXXXX"); then
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi
        if ! { feed_generated_header && LC_ALL=C sort -u "$combined"; } > "$staged" || ! feed_install "$staged" "$out_file"; then
            rm -f "$staged"
            rm -rf "$eco_tmp"
            failed=1
            continue
        fi

        line_count=$(grep -c '^pkg:' "$out_file")
        echo "  → $base: $line_count entries" >&2

        rm -rf "$eco_tmp"
    done

    echo "OSV processing complete" >&2
    return "$failed"
}

# Runtimes whose own advisories are tracked (purl type "runtime"). The names
# are Bitnami package names; add one here to cover another runtime.
RUNTIME_FEED_PACKAGES="node php"

# Fetch runtime advisories (Node.js, PHP, ...) from the OSV Bitnami ecosystem,
# which carries the upstream version ranges of each runtime CVE.
# Writes ${FEED_OUTPUT_DIR:-data}/osv-runtime.purl (pkg:runtime/<name>@<range>).
# Only BIT-<name>-<year>-* advisories are extracted: the BIT-<name>-min-*
# copies describe the same CVEs for Bitnami's minimal images.
fetch_runtime() {
    command -v jq >/dev/null 2>&1 || { echo "Error: jq is required to generate feeds" >&2; return 1; }
    local out_dir
    out_dir=$(feed_output_dir) || { echo "Error: unable to create the feed directory" >&2; return 1; }

    local out_file="$out_dir/osv-runtime.purl" tmp pkg names="" staged line_count
    local -a patterns=()
    for pkg in $RUNTIME_FEED_PACKAGES; do
        patterns+=("BIT-$pkg-[0-9]*")
        names="${names:+$names|}$pkg"
    done
    tmp=$(mktemp -d) || return 1
    register_temp_dir "$tmp"

    echo "Fetching OSV Bitnami runtime vulnerabilities ($RUNTIME_FEED_PACKAGES)..." >&2
    if ! curl -fsSL --connect-timeout 10 --max-time 300 "https://osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip" -o "$tmp/all.zip"; then
        echo "⚠️  Failed to download the OSV Bitnami feed; previous runtime feed preserved" >&2
        rm -rf "$tmp"
        return 1
    fi
    mkdir "$tmp/advisories"
    if ! unzip -q "$tmp/all.zip" "${patterns[@]}" -d "$tmp/advisories" 2>/dev/null; then
        echo "⚠️  Failed to extract the runtime advisories; previous runtime feed preserved" >&2
        rm -rf "$tmp"
        return 1
    fi

    if ! feed_emit_raw "$tmp/advisories" "osv" '{"Bitnami":"runtime"}' "$tmp/combined.purl"; then
        rm -rf "$tmp"
        return 1
    fi
    staged=$(mktemp "$out_file.tmp.XXXXXX") || { rm -rf "$tmp"; return 1; }
    # Other Bitnami packages listed in the same advisories are dropped.
    if ! { feed_generated_header && { grep -E "^pkg:runtime/($names)@" "$tmp/combined.purl" || true; } | LC_ALL=C sort -u; } > "$staged" ||
        ! feed_install "$staged" "$out_file"; then
        echo "⚠️  No runtime advisory could be generated; previous runtime feed preserved" >&2
        rm -f "$staged"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    line_count=$(grep -c '^pkg:' "$out_file")
    echo "  → osv-runtime.purl: $line_count entries" >&2
}

# Main orchestration function to fetch all PURL vulnerability feeds
# (GHSA + OSV) for every supported ecosystem.
fetch_all() {
    local output_dir="${1:-data}"

    echo "========================================="
    echo "Vulnerability PURL Feed Generator"
    echo "========================================="
    echo ""

    mkdir -p "$output_dir" || return 1

    export FEED_OUTPUT_DIR="$output_dir"
    # One "# generated:" date for every feed of this run.
    FEED_GENERATED_AT=""
    feed_generated_header > /dev/null

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

    # Generate the runtime feed (Node.js, PHP: OSV Bitnami advisories)
    echo "Generating the runtime feed..."
    fetch_runtime || status=1
    echo ""

    unset FEED_OUTPUT_DIR

    echo "========================================="
    echo "Feed generation complete!"
    echo "========================================="
    echo "Per-ecosystem totals:"
    local f count total=0
    for f in "$output_dir"/*.purl; do
        [ -e "$f" ] || continue
        count=$(grep -c '^pkg:' "$f") || count=0
        total=$((total + count))
        printf '  - %-24s %s\n' "$(basename "$f")" "$count"
    done
    echo "  ---------------------------------------"
    printf '  - %-24s %s\n' "TOTAL" "$total"
    echo ""
    [ "$status" -eq 0 ] || echo "⚠️  Some feeds could not be generated; previous files were kept" >&2
    return "$status"
}

# ---- Feed dates and freshness ----
# A published feed starts with "# generated: <UTC ISO 8601>" (when the
# update-feeds workflow built it); a copy this script downloads also carries
# "# fetched: <UTC ISO 8601>". Both are comments to every parser, old ones
# included. The content date (JSON "date"/"age_days") is the generated date,
# else the fetched date, else the file mtime (feeds without a header). A copy
# is fresh while its newest known date is within --max-feed-age: a months-old
# feed copied or checked out today is stale, and a copy fetched today of a
# feed the workflow did not rebuild is not downloaded again.
# Dates are computed in bash arithmetic: no date or stat process per feed.

# Days since 1970-01-01 of a proleptic Gregorian date. Sets DAYS_FROM_CIVIL.
days_from_civil() {
    local y="$1" m="$2" d="$3" era yoe doy doe
    [ "$m" -gt 2 ] || y=$((y - 1))
    era=$(( (y >= 0 ? y : y - 399) / 400 ))
    yoe=$(( y - era * 400 ))
    doy=$(( (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1 ))
    doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
    DAYS_FROM_CIVIL=$(( era * 146097 + doe - 719468 ))
}

# Epoch seconds of a "YYYY-MM-DDTHH:MM:SSZ" time. Sets ISO_EPOCH; non-zero
# when the text has another shape.
iso_to_epoch() {
    ISO_EPOCH=""
    [[ "$1" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$ ]] || return 1
    local hh=$((10#${BASH_REMATCH[4]})) mm=$((10#${BASH_REMATCH[5]})) ss=$((10#${BASH_REMATCH[6]}))
    days_from_civil $((10#${BASH_REMATCH[1]})) $((10#${BASH_REMATCH[2]})) $((10#${BASH_REMATCH[3]}))
    ISO_EPOCH=$(( DAYS_FROM_CIVIL * 86400 + hh * 3600 + mm * 60 + ss ))
}

# UTC ISO 8601 form of an epoch time (>= 0). Sets EPOCH_ISO.
epoch_to_iso() {
    local t="$1" z era doe yoe y doy mp d m s
    z=$(( t / 86400 + 719468 ))
    s=$(( t % 86400 ))
    era=$(( z / 146097 ))
    doe=$(( z - era * 146097 ))
    yoe=$(( (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365 ))
    doy=$(( doe - (365 * yoe + yoe / 4 - yoe / 100) ))
    mp=$(( (5 * doy + 2) / 153 ))
    d=$(( doy - (153 * mp + 2) / 5 + 1 ))
    m=$(( mp < 10 ? mp + 3 : mp - 9 ))
    y=$(( yoe + era * 400 + (m <= 2 ? 1 : 0) ))
    printf -v EPOCH_ISO '%04d-%02d-%02dT%02d:%02d:%02dZ' "$y" "$m" "$d" $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
}

# The current time, read once per run (printf builtin: no process). Sets
# NOW_EPOCH.
feed_clock() {
    [ -z "${NOW_EPOCH:-}" ] || return 0
    printf -v NOW_EPOCH '%(%s)T' -1 2>/dev/null || NOW_EPOCH=""
    case "$NOW_EPOCH" in ''|*[!0-9]*) NOW_EPOCH=$(date +%s) ;; esac
}

# Modification time of a file in seconds since the epoch (GNU, BSD and
# busybox stat; the flavour is probed once). Sets FILE_MTIME, empty when it
# cannot be read.
file_mtime_epoch() {
    FILE_MTIME=""
    if [ -z "${STAT_FLAVOR:-}" ]; then
        if stat -c %Y / > /dev/null 2>&1; then STAT_FLAVOR=gnu; else STAT_FLAVOR=bsd; fi
    fi
    if [ "$STAT_FLAVOR" = gnu ]; then
        FILE_MTIME=$(stat -c %Y "$1" 2>/dev/null) || FILE_MTIME=""
    else
        FILE_MTIME=$(stat -f %m "$1" 2>/dev/null) || FILE_MTIME=""
    fi
    case "$FILE_MTIME" in *[!0-9]*) FILE_MTIME="" ;; esac
}

# Dates of one feed file. Sets FEED_META_DATE (content date, ISO),
# FEED_META_AGE (its age in whole days) and FEED_META_REF (the newest known
# date, epoch, for freshness); all empty when unknown.
feed_file_meta() {
    local file="$1" line n=0 generated="" fetched="" content
    FEED_META_DATE="" FEED_META_AGE="" FEED_META_REF=""
    feed_clock
    if [ -r "$file" ]; then
        # Header comments come first: read a few lines with the builtin.
        while [ "$n" -lt 4 ] && IFS= read -r line; do
            n=$((n + 1))
            case "$line" in
                '# generated: '*) ! iso_to_epoch "${line#\# generated: }" || generated="$ISO_EPOCH" ;;
                '# fetched: '*) ! iso_to_epoch "${line#\# fetched: }" || fetched="$ISO_EPOCH" ;;
                '#'*) ;;
                *) break ;;
            esac
        done < "$file"
    fi
    content="${generated:-$fetched}"
    if [ -z "$content" ]; then
        file_mtime_epoch "$file"
        content="$FILE_MTIME"
    fi
    [ -n "$content" ] || return 0
    FEED_META_REF="$content"
    [ -z "$fetched" ] || [ "$fetched" -le "$content" ] || FEED_META_REF="$fetched"
    epoch_to_iso "$content"
    FEED_META_DATE="$EPOCH_ISO"
    FEED_META_AGE=$(( (NOW_EPOCH - content) / 86400 ))
    [ "$FEED_META_AGE" -ge 0 ] || FEED_META_AGE=0
}

# True when the file last described by feed_file_meta is within
# --max-feed-age (always with 0, or when its date is unknown).
feed_meta_fresh() {
    [ "$MAX_FEED_AGE_DAYS" -gt 0 ] && [ -n "$FEED_META_REF" ] || return 0
    [ $((NOW_EPOCH - FEED_META_REF)) -le $((MAX_FEED_AGE_DAYS * 86400)) ]
}

# Base URL of the published feeds (refreshed by the update-feeds workflow).
FEED_REMOTE_BASE="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data"

# Per-user directory where downloaded feeds are kept between runs (when no
# writable --data-dir is given): PACKAGE_CHECKER_CACHE_DIR, else
# ${XDG_CACHE_HOME:-$HOME/.cache}/package-checker/feeds. Sets FEED_CACHE_DIR
# (empty when there is none).
resolve_feed_cache_dir() {
    [ -z "${FEED_CACHE_DIR+x}" ] || return 0
    FEED_CACHE_DIR="${PACKAGE_CHECKER_CACHE_DIR:-}"
    if [ -z "$FEED_CACHE_DIR" ]; then
        local base="${XDG_CACHE_HOME:-}"
        case "$base" in /*) ;; *) base="${HOME:+$HOME/.cache}" ;; esac
        [ -z "$base" ] || FEED_CACHE_DIR="$base/package-checker/feeds"
    fi
    FEED_CACHE_DIR="${FEED_CACHE_DIR%/}"
}

# Resolve, once and in the calling shell, what the feed lookup needs: the
# clock, the script's own directory and the cache directory (brew --prefix is
# only asked when a feed has no fresh copy before the Homebrew directory).
prepare_default_source_lookup() {
    feed_clock
    resolve_script_home
    resolve_feed_cache_dir
}

# Directory a downloaded feed is written to, chosen once: --data-dir when it
# is writable, else the cache directory, else a temporary directory (the
# download then serves this run only). Leftover staging files of a killed
# run are removed. Sets FEED_WRITE_DIR.
resolve_feed_write_dir() {
    [ -z "${FEED_WRITE_DIR:-}" ] || return 0
    local dir
    for dir in "${FEED_DATA_DIR%/}" "$FEED_CACHE_DIR"; do
        [ -n "$dir" ] || continue
        if [ "$dir" = "$FEED_CACHE_DIR" ]; then mkdir -p "$dir" 2>/dev/null || continue; fi
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            FEED_WRITE_DIR="$dir"
            feed_remove_stale_staging "$dir"
            return 0
        fi
    done
    FEED_WRITE_DIR=$(mktemp -d) || return 1
    register_temp_dir "$FEED_WRITE_DIR"
}

# Staging files (.<feed>.purl.tmp.XXXXXX) left by a run killed during a
# download (SIGKILL skips the cleanup trap). 15 minutes exceeds the longest
# download, so a concurrent run is not disturbed.
feed_remove_stale_staging() {
    find "$1" -maxdepth 1 -name '.*.purl.tmp.*' -type f -mmin +15 -exec rm -f {} + 2>/dev/null || true
}

# Download one published feed into DIR (atomic: a staging file renamed over
# the previous copy only when it is a complete purl feed), with a
# "# fetched:" header. Arguments: feed name, directory, curl --max-time and
# --connect-timeout (default 10). Sets FEED_FETCH_STATUS to curl's exit
# status (0 when the download itself succeeded).
feed_fetch_into() {
    local name="$1" dir="$2" max_time="$3" connect_timeout="${4:-10}" staged stamp
    FEED_FETCH_STATUS=0
    feed_clock
    epoch_to_iso "$NOW_EPOCH"
    stamp="$EPOCH_ISO"
    staged=$(mktemp "$dir/.$name.tmp.XXXXXX") || return 1
    register_temp_file "$staged"
    { printf '# fetched: %s\n' "$stamp" &&
        curl -fsSL --connect-timeout "$connect_timeout" --max-time "$max_time" "$FEED_REMOTE_BASE/$name"; } > "$staged" ||
        FEED_FETCH_STATUS=$?
    if [ "$FEED_FETCH_STATUS" -ne 0 ]; then
        rm -f "$staged"
        return 1
    fi
    feed_install "$staged" "$dir/$name"
}

# Remember, for the rest of the run, a curl failure that is not an HTTP
# error (22): GitHub could not be reached or did not answer in time.
feed_note_remote_failure() {
    case "$1" in
        0|22) ;;
        *) FEED_REMOTE_UNREACHABLE=true ;;
    esac
}

# Resolve one default feed (e.g. "ghsa.purl", "osv-pypi.purl"), in the
# calling shell. Local copies, in order:
# 1. --data-dir / PACKAGE_CHECKER_DATA_DIR
# 2. the data/ directory next to this script (symlinks resolved: a git
#    checkout, a release, Homebrew or Docker through their symlinks)
# 3. the Homebrew installation path
# 4. the Docker /app/data/ directory
# 5. the download cache (see resolve_feed_cache_dir)
# The first fresh copy (see feed_file_meta) wins. Otherwise the published
# feed is downloaded and kept (resolve_feed_write_dir), so the next runs use
# it; when the download fails, the newest stale copy is used, with a warning.
# A connection failure or timeout is remembered for the run
# (FEED_REMOTE_UNREACHABLE): the next feeds are not tried again.
# With no local copy at all and GitHub unreachable, ./data/ in the current
# directory is a last resort (offline piped run), with a warning: the scanned
# project is usually the current directory, and its own data/ must never
# replace the built-in feeds while those can be reached.
# Sets FEED_PATH (the file to read, empty when none), FEED_ORIGIN (the path,
# or the URL of a download), FEED_STALE (true when a stale copy is used) and,
# when FEED_PATH is empty, FEED_FAILURE (missing or failed). Returns non-zero
# when no copy can be used.
resolve_default_feed() {
    local name="$1" dir file data_dir="${FEED_DATA_DIR%/}"
    local stale="" stale_ref=-1 stale_age="" data_dir_note=""
    FEED_PATH="" FEED_ORIGIN="" FEED_STALE=false FEED_FAILURE=missing
    prepare_default_source_lookup

    local -a dirs=()
    [ -z "$data_dir" ] || dirs+=("$data_dir")
    [ -z "$SCRIPT_HOME" ] || dirs+=("$SCRIPT_HOME/data")
    dirs+=(@brew /app/data)
    [ -z "$FEED_CACHE_DIR" ] || dirs+=("$FEED_CACHE_DIR")

    for dir in "${dirs[@]}"; do
        if [ "$dir" = @brew ]; then
            resolve_brew_prefix
            [ -n "$BREW_PREFIX" ] || continue
            dir="$BREW_PREFIX/share/package-checker/data"
        fi
        file="$dir/$name"
        if [ ! -f "$file" ]; then
            [ "$dir" != "$data_dir" ] || data_dir_note="$data_dir has no $name"
            continue
        fi
        feed_file_meta "$file"
        if feed_meta_fresh; then
            [ -z "$data_dir_note" ] ||
                echo -e "${YELLOW}⚠️  Warning: $data_dir_note; using $file${NC}" >&2
            FEED_PATH="$file" FEED_ORIGIN="$file"
            return 0
        fi
        [ "$dir" != "$data_dir" ] || data_dir_note="$file is ${FEED_META_AGE:-?} day(s) old"
        if [ "${FEED_META_REF:-0}" -gt "$stale_ref" ]; then
            stale="$file" stale_ref="${FEED_META_REF:-0}" stale_age="${FEED_META_AGE:-?}"
        fi
    done

    local url="$FEED_REMOTE_BASE/$name" probe=0 connect_timeout=10
    if [ -z "$stale" ]; then
        if [ "$FEED_REMOTE_UNREACHABLE" = true ]; then
            probe=1
        else
            curl --output /dev/null --silent --head --fail --connect-timeout 10 --max-time 30 "$url" 2>/dev/null || probe=$?
            feed_note_remote_failure "$probe"
        fi
        if [ "$probe" -ne 0 ]; then
            if [ -f "./data/$name" ]; then
                echo -e "${YELLOW}⚠️  Warning: built-in feeds unreachable; using ./data/$name from the current directory${NC}" >&2
                FEED_PATH="./data/$name" FEED_ORIGIN="./data/$name"
                return 0
            fi
            [ -z "$data_dir_note" ] || echo -e "${YELLOW}⚠️  Warning: $data_dir_note${NC}" >&2
            return 1
        fi
    elif [ "$FEED_REMOTE_UNREACHABLE" = true ]; then
        echo -e "${YELLOW}⚠️  Warning: using $stale, $stale_age day(s) old (--max-feed-age $MAX_FEED_AGE_DAYS): GitHub could not be reached earlier in this run; refresh it with --update-feeds --data-dir DIR${NC}" >&2
        FEED_PATH="$stale" FEED_ORIGIN="$stale" FEED_STALE=true
        return 0
    else
        echo -e "${YELLOW}⚠️  Warning: $stale is $stale_age day(s) old (older than $MAX_FEED_AGE_DAYS day(s)); downloading the current feed${NC}" >&2
        # A usable copy is at hand: do not wait long for a connection.
        connect_timeout=5
    fi

    FEED_FETCH_STATUS=0
    if resolve_feed_write_dir && feed_fetch_into "$name" "$FEED_WRITE_DIR" 120 "$connect_timeout"; then
        FEED_PATH="$FEED_WRITE_DIR/$name" FEED_ORIGIN="$url"
        return 0
    fi
    feed_note_remote_failure "$FEED_FETCH_STATUS"
    echo -e "${RED}❌ Error: Unable to download from $url${NC}" >&2
    if [ -n "$stale" ]; then
        echo -e "${YELLOW}⚠️  Warning: using $stale, $stale_age day(s) old (--max-feed-age $MAX_FEED_AGE_DAYS): the current feed could not be downloaded; refresh it with --update-feeds --data-dir DIR${NC}" >&2
        FEED_PATH="$stale" FEED_ORIGIN="$stale" FEED_STALE=true
        return 0
    fi
    FEED_FAILURE=failed FEED_ORIGIN="$url"
    return 1
}

# "Using ... source" line of the feed resolve_default_feed chose.
feed_using_line() {
    if [ "$FEED_ORIGIN" != "$FEED_PATH" ]; then
        echo -e "${GREEN}✓ Using $1 source: $FEED_ORIGIN (downloaded to $FEED_PATH)${NC}"
    else
        echo -e "${GREEN}✓ Using $1 source: $FEED_PATH${NC}"
    fi
    echo ""
}

# Print the file resolve_default_feed would read for one feed (diagnostics
# and tests); non-zero when there is none.
find_default_source() {
    resolve_default_feed "$1" || return 1
    printf '%s\n' "$FEED_PATH"
}

# Record one data source for the JSON report ("sources"). Arguments: kind,
# ecosystem, feed file name, display name, status, origin (path or URL),
# entry count, the local file read (for its dates; default: the origin) and
# whether a stale copy was used. A remote custom source is dated now.
record_feed_source() {
    local kind="$1" eco="$2" file="$3" name="$4" status="$5" origin="$6" entries="${7:-0}"
    local meta_file="${8:-$6}" stale="${9:-false}" date="" age=""
    if [ "$status" = loaded ]; then
        if [ -f "$meta_file" ]; then
            feed_file_meta "$meta_file"
            date="$FEED_META_DATE" age="$FEED_META_AGE"
        elif [[ "$origin" =~ ^(https?|ftp):// ]]; then
            feed_clock
            epoch_to_iso "$NOW_EPOCH"
            date="$EPOCH_ISO" age=0
        fi
    fi
    [ "$kind" != custom ] || stale=false
    local sep=$'\x1f'
    FEED_SOURCES+=("$kind$sep$eco$sep$file$sep$name$sep$status$sep$origin$sep$entries$sep$date$sep$age$sep$stale")
}

# --update-feeds: download the published feeds (GHSA + OSV for the given purl
# types, plus the runtime feed) into DIR, each written to a temp file in DIR
# and renamed over the old copy only when the download is a complete purl
# feed. Returns non-zero when a feed could not be refreshed (its previous
# copy is kept).
update_feeds() {
    local dir="$1" feed_types="$2" t feed name failed=0 count=0
    if ! mkdir -p "$dir" 2>/dev/null || [ ! -w "$dir" ]; then
        echo -e "${RED}❌ Error: unable to write the feed directory $dir${NC}" >&2
        return 2
    fi
    feed_remove_stale_staging "$dir"
    local -a names=()
    for t in $feed_types; do
        for feed in ghsa osv; do
            names+=("$(default_feed_filename "$feed" "$t")")
        done
    done
    names+=("osv-runtime.purl")
    for name in "${names[@]}"; do
        if feed_fetch_into "$name" "$dir" 600; then
            count=$((count + 1))
            echo "  ✓ $name: $(grep -c '^pkg:' "$dir/$name") entries"
        else
            echo -e "${YELLOW}⚠️  Unable to download $name; previous copy kept${NC}" >&2
            failed=1
        fi
    done
    echo "Updated $count of ${#names[@]} feed(s) in $dir"
    return "$failed"
}

# Main execution
