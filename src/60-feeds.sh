# ============================================================================
# Vulnerability Feed Generation Functions
# ============================================================================

# Fetch GitHub Security Advisory data for npm ecosystem
# Outputs PURL-formatted vulnerabilities to stdout
fetch_ghsa() {
    local output_file="${1:-data/ghsa.purl}"

    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"

    # Convert to absolute path to handle directory changes
    output_file=$(cd "$(dirname "$output_file")" 2>/dev/null && pwd)/$(basename "$output_file")

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    GHSA_REPO="https://github.com/github/advisory-database.git"
    CLONE_DIR="$TEMP_DIR/advisory-database"

    echo "Cloning GitHub Advisory Database (all reviewed advisories)..." >&2

    # Shallow clone with sparse checkout for all reviewed advisories
    git clone --filter=blob:none --no-checkout --depth 1 "$GHSA_REPO" "$CLONE_DIR" 2>&1 | grep -v "^remote:" | grep -v "^Cloning" | grep -v "^$" || true
    cd "$CLONE_DIR"
    git sparse-checkout init --cone 2>&1 | grep -v "^$" || true
    git sparse-checkout set advisories/github-reviewed 2>&1 | grep -v "^$" || true
    git checkout 2>&1 | grep -v "^remote:" | grep -v "^Your branch" | grep -v "^$" || true

    echo "Processing GHSA npm advisories..." >&2

    # Count files for progress
    file_count=$(find advisories/github-reviewed -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count advisory files" >&2

    # Process each JSON file in the npm directories
    count=0
    find advisories/github-reviewed -name "*.json" -type f | while read -r json_file; do
        count=$((count + 1))
        if [ $((count % 100)) -eq 0 ]; then
            echo "Processed $count/$file_count files..." >&2
        fi

        jq -r '
            # Extract metadata
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

            # Extract aliases (CVE)
            (.aliases // []) as $aliases |
            ($aliases | map(select(startswith("CVE-"))) | .[0] // "") as $cve |
            # GHSA ID is the main ID for GitHub advisories
            (if $id | startswith("GHSA-") then $id else "" end) as $ghsa |

            .affected[]? |
            select(.package.ecosystem == "npm") |
            .package.name as $pkg |
            (
                (.ranges[]? |
                    select(.type == "SEMVER" or .type == "ECOSYSTEM") |
                    .events |
                    # Convert events array to version range
                    map(select(.introduced or .fixed or .last_affected)) |
                    if length > 0 then
                        # Build range from events
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
                        # Build query params
                        ([
                            ("severity=" + ($severity | ascii_downcase)),
                            (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                            (if $cve != "" then "cve=" + $cve else empty end),
                            ("source=ghsa")
                        ] | join("&")) as $params |

                        # Format as PURL with query params
                        if .introduced and .fixed then
                            "pkg:npm/\($pkg)@>=\(.introduced) <\(.fixed)?\($params)"
                        elif .introduced and .last_affected then
                            "pkg:npm/\($pkg)@>=\(.introduced) <=\(.last_affected)?\($params)"
                        elif .introduced then
                            "pkg:npm/\($pkg)@>=\(.introduced)?\($params)"
                        elif .fixed then
                            "pkg:npm/\($pkg)@<\(.fixed)?\($params)"
                        elif .last_affected then
                            "pkg:npm/\($pkg)@<=\(.last_affected)?\($params)"
                        else empty end
                    else empty end
                ),
                # Output exact versions for entries without SEMVER/ECOSYSTEM ranges (e.g., MAL advisories)
                (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
                    ([
                        ("severity=" + ($severity | ascii_downcase)),
                        (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                        (if $cve != "" then "cve=" + $cve else empty end),
                        ("source=ghsa")
                    ] | join("&")) as $params |
                    .versions[]? |
                    "pkg:npm/\($pkg)@\(.)?\($params)"
                else empty end)
            )
        ' "$json_file" 2>/dev/null || true
    done | sort -u > "$output_file"

    echo "Processed all $file_count files" >&2
    echo "GHSA processing complete" >&2

    cd - > /dev/null
}

# Fetch OSV vulnerability data for npm ecosystem
# Outputs PURL-formatted vulnerabilities to stdout
fetch_osv() {
    local output_file="${1:-data/osv.purl}"

    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"

    # Convert to absolute path to handle directory changes
    output_file=$(cd "$(dirname "$output_file")" 2>/dev/null && pwd)/$(basename "$output_file")

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    OSV_URL="https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
    OUTPUT_FILE="$TEMP_DIR/npm.zip"

    echo "Fetching OSV npm vulnerabilities..." >&2
    curl -sL "$OSV_URL" -o "$OUTPUT_FILE"

    echo "Extracting vulnerabilities..." >&2
    unzip -q "$OUTPUT_FILE" -d "$TEMP_DIR"

    echo "Processing vulnerabilities..." >&2

    # Count files for progress
    file_count=$(find "$TEMP_DIR" -name "*.json" -type f | wc -l | tr -d ' ')
    echo "Found $file_count vulnerability files" >&2
    echo "Using parallel processing to speed up extraction..." >&2

    # Process files in parallel using xargs (8 parallel workers)
    find "$TEMP_DIR" -name "*.json" -type f -print0 | \
    xargs -0 -P 8 -I {} jq -r '
        # Extract metadata
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

        # Extract aliases (GHSA, CVE)
        (.aliases // []) as $aliases |
        ($aliases | map(select(startswith("GHSA-"))) | .[0] // "") as $ghsa |
        ($aliases | map(select(startswith("CVE-"))) | .[0] // "") as $cve |

        .affected[]? |
        select(.package.ecosystem == "npm") |
        .package.name as $pkg |
        (
            (.ranges[]? |
                select(.type == "SEMVER" or .type == "ECOSYSTEM") |
                .events |
                # Convert events array to version range
                map(select(.introduced or .fixed or .last_affected)) |
                if length > 0 then
                    # Build range from events
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
                    # Build query params
                    ([
                        ("severity=" + ($severity | ascii_downcase)),
                        (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                        (if $cve != "" then "cve=" + $cve else empty end),
                        ("source=osv")
                    ] | join("&")) as $params |

                    # Format as PURL with query params
                    if .introduced and .fixed then
                        "pkg:npm/\($pkg)@>=\(.introduced) <\(.fixed)?\($params)"
                    elif .introduced and .last_affected then
                        "pkg:npm/\($pkg)@>=\(.introduced) <=\(.last_affected)?\($params)"
                    elif .introduced then
                        "pkg:npm/\($pkg)@>=\(.introduced)?\($params)"
                    elif .fixed then
                        "pkg:npm/\($pkg)@<\(.fixed)?\($params)"
                    elif .last_affected then
                        "pkg:npm/\($pkg)@<=\(.last_affected)?\($params)"
                    else empty end
                else empty end
            ),
            # Output exact versions for entries without SEMVER/ECOSYSTEM ranges (e.g., MAL advisories)
            (if ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM")] | length) == 0 then
                ([
                    ("severity=" + ($severity | ascii_downcase)),
                    (if $ghsa != "" then "ghsa=" + $ghsa else empty end),
                    (if $cve != "" then "cve=" + $cve else empty end),
                    ("source=osv")
                ] | join("&")) as $params |
                .versions[]? |
                "pkg:npm/\($pkg)@\(.)?\($params)"
            else empty end)
        )
    ' {} 2>/dev/null | sort -u > "$output_file"

    echo "Processed all $file_count files" >&2
    echo "OSV processing complete" >&2
}

# Main orchestration function to fetch all PURL vulnerability feeds
# This function runs the individual fetchers and updates the feed files
fetch_all() {
    local output_dir="${1:-data}"

    echo "========================================="
    echo "Vulnerability PURL Feed Generator"
    echo "========================================="
    echo ""

    # Ensure output directory exists
    mkdir -p "$output_dir"

    # Generate OSV feed
    echo "Generating OSV npm feed..."
    fetch_osv "$output_dir/osv.purl"
    OSV_COUNT=$(wc -l < "$output_dir/osv.purl" | tr -d ' ')
    echo "✓ OSV feed generated: $OSV_COUNT vulnerabilities"
    echo ""

    # Generate GHSA feed
    echo "Generating GHSA npm feed..."
    fetch_ghsa "$output_dir/ghsa.purl"
    GHSA_COUNT=$(wc -l < "$output_dir/ghsa.purl" | tr -d ' ')
    echo "✓ GHSA feed generated: $GHSA_COUNT vulnerabilities"
    echo ""

    echo "========================================="
    echo "Feed generation complete!"
    echo "========================================="
    echo "Total vulnerabilities:"
    echo "  - OSV:  $OSV_COUNT"
    echo "  - GHSA: $GHSA_COUNT"
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
