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

# Replace a feed file with a staged one, atomically, only when the staged file
# has content: an empty result means a broken download or parse, not a feed
# with no advisory. Feed files are world-readable like committed ones (mktemp
# creates them 0600). Returns non-zero when the previous file was kept.
feed_install() {
    local staged="$1" out_file="$2"
    if [ ! -s "$staged" ]; then
        echo "⚠️  No entry generated for ${out_file##*/}; previous file preserved" >&2
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
        if ! { grep "^pkg:$t/" "$combined" || true; } | LC_ALL=C sort -u > "$staged" ||
            ! feed_install "$staged" "$out_file"; then
            rm -f "$staged"
            failed=1
            continue
        fi
        line_count=$(wc -l < "$out_file" | tr -d ' ')
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
        if ! LC_ALL=C sort -u "$combined" > "$staged" || ! feed_install "$staged" "$out_file"; then
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
    if ! { grep -E "^pkg:runtime/($names)@" "$tmp/combined.purl" || true; } | LC_ALL=C sort -u > "$staged" ||
        ! feed_install "$staged" "$out_file"; then
        echo "⚠️  No runtime advisory could be generated; previous runtime feed preserved" >&2
        rm -f "$staged"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    line_count=$(wc -l < "$out_file" | tr -d ' ')
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

# find_default_source runs in command substitutions: resolve the installation
# paths it probes once, in the calling shell, so they are not recomputed
# (brew --prefix) for every feed. Only needed when a built-in feed is loaded.
prepare_default_source_lookup() {
    resolve_script_home
    [ -d "$SCRIPT_HOME/data" ] || resolve_brew_prefix
}

# Find default source file with fallback logic. Tries, in order:
# 1. the data/ directory next to this script (symlinks resolved: a git
#    checkout, a release, Homebrew or Docker through their symlinks)
# 2. the Homebrew installation path
# 3. the Docker /app/data/ directory
# 4. the remote GitHub URL
# 5. ./data/ in the current directory, only when nothing else is reachable
#    (offline piped run), with a warning
# The scanned project is usually the current directory: its own data/ must
# never replace the built-in feeds while those can be reached.
# Returns path/URL if found, empty string if not found
find_default_source() {
    local source_file="$1"  # e.g., "ghsa.purl" or "osv.purl"

    resolve_script_home
    if [ -n "$SCRIPT_HOME" ] && [ -f "$SCRIPT_HOME/data/$source_file" ]; then
        echo "$SCRIPT_HOME/data/$source_file"
        return 0
    fi

    resolve_brew_prefix
    if [ -n "$BREW_PREFIX" ] && [ -f "$BREW_PREFIX/share/package-checker/data/$source_file" ]; then
        echo "$BREW_PREFIX/share/package-checker/data/$source_file"
        return 0
    fi

    # Try Docker /app/data/ directory
    if [ -f "/app/data/$source_file" ]; then
        echo "/app/data/$source_file"
        return 0
    fi

    local github_url="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/$source_file"
    if curl --output /dev/null --silent --head --fail --connect-timeout 10 --max-time 30 "$github_url" 2>/dev/null; then
        echo "$github_url"
        return 0
    fi

    if [ -f "./data/$source_file" ]; then
        echo -e "${YELLOW}⚠️  Warning: built-in feeds unreachable; using ./data/$source_file from the current directory${NC}" >&2
        echo "./data/$source_file"
        return 0
    fi

    # Nothing found
    echo ""
    return 1
}

# Main execution
