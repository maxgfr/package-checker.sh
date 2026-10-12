# GitHub API functions
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_ORG="${GITHUB_ORG:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_OUTPUT_DIR="${GITHUB_OUTPUT_DIR:-./packages}"
GITHUB_ONLY=false
GITHUB_RATE_LIMIT_DELAY=2
CREATE_GITHUB_ISSUE=false
CREATE_SINGLE_ISSUE=false

# Make a GitHub API request with automatic retry on rate limit. A 403/429
# rate-limit answer waits until the time GitHub gives (Retry-After or
# x-ratelimit-reset), capped by GITHUB_RATE_LIMIT_MAX_WAIT seconds.
GITHUB_RATE_LIMIT_MAX_WAIT="${GITHUB_RATE_LIMIT_MAX_WAIT:-900}"
github_request() {
    local url="$1"
    local max_retries=3
    local attempt=1
    local response http_code headers wait_time value

    while [ $attempt -le $max_retries ]; do
        headers=$(mktemp) || return 1
        register_temp_file "$headers"
        if ! response=$(curl -sS --connect-timeout 10 --max-time 60 -D "$headers" -w "\n%{http_code}" \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: package-checker-script" \
            "$url"); then
            rm -f -- "$headers"
            echo "Error: Unable to reach GitHub API" >&2
            return 1
        fi

        http_code="${response##*$'\n'}"
        response="${response%$'\n'*}"

        if [ "$http_code" = "200" ]; then
            rm -f -- "$headers"
            echo "$response"
            return 0
        fi

        # Handle rate limiting (403 or 429)
        if { [ "$http_code" = 429 ] || { [ "$http_code" = 403 ] &&
            { [[ "$response" == *"rate limit"* ]] || grep -qi '^x-ratelimit-remaining:[[:space:]]*0' "$headers"; }; }; } &&
            [ $attempt -lt $max_retries ]; then
            wait_time=60
            value=$(awk 'tolower($1) == "retry-after:" { gsub(/\r/, "", $2); print $2 }' "$headers")
            if [[ "$value" =~ ^[0-9]+$ ]]; then
                wait_time=$value
            else
                value=$(awk 'tolower($1) == "x-ratelimit-reset:" { gsub(/\r/, "", $2); print $2 }' "$headers")
                if [[ "$value" =~ ^[0-9]+$ ]]; then
                    wait_time=$(( value - $(date +%s) + 1 ))
                    [ "$wait_time" -ge 1 ] || wait_time=1
                fi
            fi
            rm -f -- "$headers"
            if [ "$wait_time" -gt "$GITHUB_RATE_LIMIT_MAX_WAIT" ]; then
                echo -e "${RED}❌ GitHub rate limit resets in ${wait_time}s (more than ${GITHUB_RATE_LIMIT_MAX_WAIT}s); giving up${NC}" >&2
                return 1
            fi
            echo -e "${YELLOW}⚠️  Rate limit hit, waiting ${wait_time}s before retry ($attempt/$max_retries)...${NC}" >&2
            sleep "$wait_time"
            attempt=$((attempt + 1))
            continue
        fi
        rm -f -- "$headers"

        # Non-retryable error or max retries reached
        echo -e "${RED}❌ GitHub API error ($http_code): $response${NC}" >&2
        return 1
    done

    return 1
}

# Get all repositories from a GitHub organization
# OPTIMIZED: Returns newline-separated list of "name|full_name" instead of JSON
get_github_repositories() {
    echo -e "${BLUE}🔍 Fetching repositories for organization: $GITHUB_ORG${NC}" >&2
    
    local all_repos=""
    local page=1
    local per_page=100
    
    while true; do
        local url="https://api.github.com/orgs/${GITHUB_ORG}/repos?page=${page}&per_page=${per_page}"
        local repos
        
        repos=$(github_request "$url") || return 1
        
        # FIXED: Use grep -o | wc -l to count occurrences correctly (grep -c counts lines, not occurrences)
        local count=$(echo "$repos" | grep -o '"full_name"' | wc -l | tr -d ' ')
        
        if [ "$count" -eq 0 ]; then
            break
        fi
        
        # OPTIMIZED: Extract name and full_name pairs using grep/sed
        # Format: name|full_name (one per line)
        local repo_pairs
        repo_pairs=$(echo "$repos" | tr '\n' ' ' | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]*"[^}]*"full_name"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            sed 's/"name"[[:space:]]*:[[:space:]]*"//;s/"[^}]*"full_name"[[:space:]]*:[[:space:]]*"/|/;s/"$//')
        
        if [ -z "$all_repos" ]; then
            all_repos="$repo_pairs"
        else
            all_repos="$all_repos"$'\n'"$repo_pairs"
        fi
        echo "   Found $count repositories on page $page" >&2
        
        if [ "$count" -lt "$per_page" ]; then
            break
        fi
        
        page=$((page + 1))
        sleep "$GITHUB_RATE_LIMIT_DELAY"
    done
    
    local total=$(echo "$all_repos" | wc -l | tr -d ' ')
    echo -e "${GREEN}✅ Total repositories found: $total${NC}" >&2
    echo "" >&2
    
    echo "$all_repos"
}

# Search for package.json and lockfiles in a repository using tree API (works without token for public repos)
search_package_json_in_repo_tree() {
    local repo_full_name="$1"
    local repo_name="$2"
    
    echo -e "   ${BLUE}Fetching repository tree...${NC}"
    
    # Get the default branch first, then pin its current commit: the tree
    # and every file then come from the same snapshot, even if the branch
    # moves while files are downloaded.
    local repo_info
    repo_info=$(github_request "https://api.github.com/repos/${repo_full_name}") || return 1
    local default_branch ref branch_info
    default_branch=$(json_get_value "$repo_info" "default_branch")
    ref="$default_branch"
    if branch_info=$(github_request "https://api.github.com/repos/${repo_full_name}/branches/${default_branch}"); then
        local commit_sha
        commit_sha=$(json_get_value "$branch_info" "sha")
        [[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] && ref="$commit_sha"
    fi

    # Get the full tree recursively
    local tree_url="https://api.github.com/repos/${repo_full_name}/git/trees/${ref}?recursive=1"
    local tree_response
    tree_response=$(github_request "$tree_url") || return 1
    if [[ "$tree_response" =~ \"truncated\"[[:space:]]*:[[:space:]]*true ]]; then
        echo "Error: GitHub returned a truncated tree for $repo_full_name" >&2
        return 1
    fi
    
    # OPTIMIZED: Use grep/sed to extract paths directly instead of slow JSON parsing
    # Extract all "path" values from the tree response and filter for target files
    # This is MUCH faster than iterating with json_array_get for large trees
    # Build the filename match regex from the ecosystem registry (+ package.json)
    local scan_regex="" _name
    for _name in $(ecosystem_scan_filenames); do
        scan_regex="${scan_regex:+$scan_regex|}${_name//./\\.}"
    done

    local target_files
    target_files=$(echo "$tree_response" | \
        grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"$//' | \
        grep -v 'node_modules' | \
        grep -E "(^|/)(${scan_regex})\$" || true)
    
    if [ -z "$target_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Count files by type
    local pkg_count=$(echo "$target_files" | grep -c "package.json" || true)
    local lock_count=$(echo "$target_files" | grep -v "package.json" | grep -c "." || true)
    echo "   Found $pkg_count package.json file(s) and $lock_count lockfile(s)"
    
    # Start from an empty repo directory: files deleted upstream since a
    # previous fetch must not be scanned again.
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    if [ -n "$repo_name" ] && [ "$repo_name" != . ] && [ "$repo_name" != .. ]; then
        rm -rf -- "$repo_dir"
    fi
    mkdir -p "$repo_dir"

    # Fetch each file
    while IFS= read -r file_path; do
        [ -z "$file_path" ] && continue

        local raw_url="https://raw.githubusercontent.com/${repo_full_name}/${ref}/${file_path}"
        local file_content
        file_content=$(curl -fsSL --connect-timeout 10 --max-time 60 \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "User-Agent: package-checker-script" \
            "${raw_url// /%20}") || return 1
        
        # Save the file
        local full_path="${repo_dir}/${file_path}"
        local dir="${full_path%/*}"
        mkdir -p "$dir"
        
        printf '%s\n' "$file_content" > "$full_path" || return 1
        
        local file_name="${file_path##*/}"
        if [ "$file_name" = "package.json" ]; then
            echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
        else
            echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
        fi
    done <<< "$target_files"
}

# Create a GitHub issue with proper JSON escaping using jq
# Arguments:
#   $1 - repo_full_name (owner/repo)
#   $2 - issue_title
#   $3 - issue_body (markdown content)
#   $4 - labels (comma-separated, optional)
create_github_issue() {
    local repo_full_name="$1"
    local issue_title="$2"
    local issue_body="$3"
    local labels="${4:-security,vulnerability}"

    if [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${YELLOW}⚠️  Cannot create issue: GitHub token is required${NC}"
        return 1
    fi

    # Check if jq is available for proper JSON escaping
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}❌ jq is required for creating issues. Please install it.${NC}"
        return 1
    fi

    # Convert labels string to JSON array
    local labels_json
    labels_json=$(echo "$labels" | tr ',' '\n' | jq -R . | jq -s .)

    # Create JSON payload with proper escaping using jq
    local json_payload
    json_payload=$(jq -n \
        --arg title "$issue_title" \
        --arg body "$issue_body" \
        --argjson labels "$labels_json" \
        '{title: $title, body: $body, labels: $labels}')

    echo -e "${BLUE}📝 Creating issue on ${repo_full_name}...${NC}"

    # Make API request to create issue
    local response
    response=$(curl -sS --connect-timeout 10 --max-time 60 -w "\n%{http_code}" -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "$json_payload" \
        "https://api.github.com/repos/${repo_full_name}/issues") || return 1
    local http_code="${response##*$'\n'}"
    response="${response%$'\n'*}"

    # Check if issue was created successfully
    if [ "$http_code" = 201 ] && echo "$response" | grep -q '"html_url"'; then
        local issue_url
        issue_url=$(echo "$response" | jq -r '.html_url // empty' 2>/dev/null || echo "$response" | grep -o '"html_url":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo -e "${GREEN}✅ Issue created: ${issue_url}${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to create issue${NC}"
        if echo "$response" | grep -q '"message"'; then
            local error_msg
            error_msg=$(echo "$response" | jq -r '.message // empty' 2>/dev/null || echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            echo -e "${RED}   Error: ${error_msg}${NC}"
        fi
        return 1
    fi
}

# Fetch all packages from GitHub organization or single repo
fetch_github_packages() {
    if [ -z "$GITHUB_ORG" ] && [ -z "$GITHUB_REPO" ]; then
        echo -e "${RED}❌ Error: GitHub organization or repository is required${NC}"
        echo "   Use --github-org for an organization or --github-repo for a single repository"
        return 1
    fi
    
    # Token is required for organization scanning (repository listing)
    if [ -n "$GITHUB_ORG" ] && [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${RED}❌ Error: GitHub token is required for organization scanning${NC}"
        echo "   Set GITHUB_TOKEN environment variable or use --github-token option"
        return 1
    fi
    
    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    echo "║       Fetching Packages from GitHub                ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""
    
    if [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${YELLOW}⚠️  No GitHub token provided - using unauthenticated requests (rate limited)${NC}"
        echo ""
    fi
    
    # Create output directory
    mkdir -p "$GITHUB_OUTPUT_DIR"
    
    # Single repository mode
    if [ -n "$GITHUB_REPO" ]; then
        # Remove trailing slash if present
        local repo_full_name="${GITHUB_REPO%/}"
        local repo_name="${repo_full_name##*/}"
        
        echo -e "${BLUE}🔍 Fetching repository: $repo_full_name${NC}"
        echo ""
        echo -e "${BLUE}Processing: $repo_name${NC}"
        
        # Use tree API for single repo (works without token for public repos)
        if ! search_package_json_in_repo_tree "$repo_full_name" "$repo_name"; then
            echo -e "${RED}❌ Failed to fetch repository: $repo_full_name${NC}"
            return 1
        fi
    else
        # Organization mode - use Tree API (less rate-limited than Search API)
        local repos
        repos=$(get_github_repositories) || return 1
        
        # OPTIMIZED: repos is now newline-separated "name|full_name" pairs
        while IFS='|' read -r repo_name repo_full_name; do
            [ -z "$repo_name" ] && continue
            
            echo -e "${BLUE}Processing: $repo_name${NC}"
            
            # Use Tree API instead of Search API (much higher rate limit). An
            # empty or unreadable repository must not stop the organization scan.
            if ! search_package_json_in_repo_tree "$repo_full_name" "$repo_name"; then
                echo -e "${YELLOW}⚠️  Skipping $repo_full_name: unable to fetch its files${NC}"
            fi
            
            sleep "$GITHUB_RATE_LIMIT_DELAY"
        done <<< "$repos"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ GitHub packages fetched to: $(realpath "$GITHUB_OUTPUT_DIR")${NC}"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# ============================================================================
# GitHub issue reports (--create-multiple-issues / --create-single-issue)
#
# Findings (VULNERABLE_PACKAGES: "file|eco|name@version") are grouped by target
# repository, then by "eco:name", then by version with the files using it.
# Every advisory of a version comes from VULN_ADVISORIES (merged GHSA/OSV
# records "severity;ghsa;cve;source;fix;id"). An issue whose exact title is
# already open in the repository is not created again.
# ============================================================================
ISSUE_REPO_LIST=()
declare -A ISSUE_REPO_PKGS=()       # repo -> newline list of eco:name
declare -A ISSUE_PKG_VERSIONS=()    # repo|eco:name -> newline list of versions
declare -A ISSUE_VERSION_FILES=()   # repo|eco:name|version -> newline list of files

# Repository (owner/repo) an issue about FILE belongs to: --github-repo, or in
# organization mode the repository whose fetched copy holds the file
# ($GITHUB_OUTPUT_DIR/<repo>/...). Sets ISSUE_REPO ("" when unknown).
issue_repository_for() {
    ISSUE_REPO=""
    if [ -n "$GITHUB_REPO" ]; then
        ISSUE_REPO="${GITHUB_REPO%/}"
        return
    fi
    [ -n "$GITHUB_ORG" ] || return 0
    local file="${1#./}" dir="${GITHUB_OUTPUT_DIR%/}/"
    dir="${dir#./}"
    [[ "$file" == "$dir"*/* ]] || return 0
    file="${file#"$dir"}"
    ISSUE_REPO="$GITHUB_ORG/${file%%/*}"
}

group_findings_for_issues() {
    ISSUE_REPO_LIST=()
    ISSUE_REPO_PKGS=()
    ISSUE_PKG_VERSIONS=()
    ISSUE_VERSION_FILES=()
    local vuln file eco pv pkg ver pk vk unknown=0
    for vuln in "${VULNERABLE_PACKAGES[@]}"; do
        IFS='|' read -r file eco pv <<< "$vuln"
        issue_repository_for "$file"
        if [ -z "$ISSUE_REPO" ]; then
            unknown=$((unknown + 1))
            continue
        fi
        pkg="$eco:${pv%@*}" ver="${pv##*@}"
        pk="$ISSUE_REPO|$pkg" vk="$ISSUE_REPO|$pkg|$ver"
        if [ -z "${ISSUE_REPO_PKGS[$ISSUE_REPO]+x}" ]; then
            ISSUE_REPO_LIST+=("$ISSUE_REPO")
            ISSUE_REPO_PKGS["$ISSUE_REPO"]=""
        fi
        if [ -z "${ISSUE_PKG_VERSIONS[$pk]+x}" ]; then
            ISSUE_REPO_PKGS["$ISSUE_REPO"]+="$pkg"$'\n'
            ISSUE_PKG_VERSIONS["$pk"]=""
        fi
        if [ -z "${ISSUE_VERSION_FILES[$vk]+x}" ]; then
            ISSUE_PKG_VERSIONS["$pk"]+="$ver"$'\n'
            ISSUE_VERSION_FILES["$vk"]="$file"
        else
            case $'\n'"${ISSUE_VERSION_FILES[$vk]}"$'\n' in
                *$'\n'"$file"$'\n'*) ;;
                *) ISSUE_VERSION_FILES["$vk"]+=$'\n'"$file" ;;
            esac
        fi
    done
    if [ "$unknown" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  ${unknown} finding(s) not attributable to a repository were left out (use --github-repo or --github-org)${NC}"
    fi
}

# Distinct advisories of one package across its versions. Sets ADV_TOTAL,
# ADV_MAX_RANK and ADV_SEV_COUNTS (index = severity rank, 0 = unknown).
package_advisory_stats() {
    local pkg="$1" versions="$2" ver advisories advisory key
    local severity ghsa cve source fix id
    local -A seen=()
    ADV_TOTAL=0 ADV_MAX_RANK=0
    ADV_SEV_COUNTS=(0 0 0 0 0)
    while IFS= read -r ver; do
        [ -n "$ver" ] || continue
        advisories="${VULN_ADVISORIES[$pkg@$ver]:-}"
        while [ -n "$advisories" ]; do
            advisory="${advisories%%||*}"
            if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
            IFS=';' read -r severity ghsa cve source fix id <<< "$advisory"
            key="${ghsa:-${cve:-${id:-$advisory}}}"
            [ -z "${seen[$key]+x}" ] || continue
            seen["$key"]=1
            severity_rank "$severity"
            ADV_SEV_COUNTS[SEV_RANK]=$(( ADV_SEV_COUNTS[SEV_RANK] + 1 ))
            ADV_TOTAL=$((ADV_TOTAL + 1))
            [ "$SEV_RANK" -le "$ADV_MAX_RANK" ] || ADV_MAX_RANK=$SEV_RANK
        done
    done <<< "$versions"
}

# Severity rank -> SEV_LABEL / SEV_EMOJI.
severity_label() {
    case "$1" in
        4) SEV_LABEL="CRITICAL" SEV_EMOJI="🔴" ;;
        3) SEV_LABEL="HIGH" SEV_EMOJI="🟠" ;;
        2) SEV_LABEL="MEDIUM" SEV_EMOJI="🟡" ;;
        1) SEV_LABEL="LOW" SEV_EMOJI="🟢" ;;
        *) SEV_LABEL="UNKNOWN" SEV_EMOJI="⚪" ;;
    esac
}

# Markdown rows of the severity summary table.
severity_summary_rows() {
    local rank rows=""
    for rank in 4 3 2 1 0; do
        [ "${ADV_SEV_COUNTS[$rank]}" -gt 0 ] || continue
        severity_label "$rank"
        rows+="| ${SEV_EMOJI} ${SEV_LABEL,,} | ${ADV_SEV_COUNTS[$rank]} |"$'\n'
    done
    printf '%s' "$rows"
}

# Markdown table of the advisories of one package version.
advisory_table() {
    local advisories="$1" advisory severity ghsa cve source fix id link
    printf '| Severity | Advisory | CVE | Source | Fixed in |\n'
    printf '|----------|----------|-----|--------|----------|\n'
    while [ -n "$advisories" ]; do
        advisory="${advisories%%||*}"
        if [ "$advisory" = "$advisories" ]; then advisories=""; else advisories="${advisories#*||}"; fi
        IFS=';' read -r severity ghsa cve source fix id <<< "$advisory"
        severity_rank "$severity"
        severity_label "$SEV_RANK"
        link="-"
        if [ -n "$ghsa" ]; then link="[${ghsa}](https://github.com/advisories/${ghsa})"
        elif [ -n "$id" ]; then link="[${id}](https://osv.dev/vulnerability/${id})"
        fi
        printf '| %s %s | %s | %s | %s | %s |\n' "$SEV_EMOJI" "${severity:-unknown}" "$link" \
            "${cve:+[${cve}](https://nvd.nist.gov/vuln/detail/${cve})}" "${source:--}" "${fix:--}"
    done
}

# Titles of the open issues of a repository (one per line), so a run does not
# file the same report twice. Empty when they cannot be listed.
open_issue_titles() {
    local repo="$1" page response titles=""
    for page in 1 2 3 4 5 6 7 8 9 10; do
        response=$(github_request "https://api.github.com/repos/${repo}/issues?state=open&per_page=100&page=${page}" 2>/dev/null) || {
            echo -e "${YELLOW}⚠️  Unable to list open issues of $repo: duplicates are not checked${NC}" >&2
            break
        }
        titles+=$(printf '%s' "$response" | jq -r '.[] | select(.pull_request == null) | .title' 2>/dev/null)$'\n'
        [ "$(printf '%s' "$response" | jq 'length' 2>/dev/null)" = 100 ] || break
    done
    printf '%s' "$titles"
}

# Create an issue unless one with the same title is open (titles in $4).
create_issue_once() {
    local repo="$1" title="$2" body="$3" open_titles="$4"
    if printf '%s\n' "$open_titles" | grep -qxF -- "$title"; then
        echo -e "${BLUE}ℹ️  Already open on ${repo}: ${title}${NC}"
        return 2
    fi
    create_github_issue "$repo" "$title" "$body" "security,vulnerability,dependencies"
}

# Body of the issue about one package (eco:name) in one repository.
package_issue_body() {
    local repo="$1" pkg="$2" versions="$3"
    local eco="${pkg%%:*}" name="${pkg#*:}" ver file body
    body="## 🔒 Security Vulnerabilities in \`${name}\` (${eco})"$'\n\n'
    body+="### 📊 Summary"$'\n\n'"| Metric | Count |"$'\n'"|--------|-------|"$'\n'
    body+="| **Total Vulnerabilities** | ${ADV_TOTAL} |"$'\n'"$(severity_summary_rows)"$'\n\n'
    body+="---"$'\n\n'"### 🔍 Vulnerability Details"$'\n\n'
    while IFS= read -r ver; do
        [ -n "$ver" ] || continue
        body+="#### Version \`${ver}\`"$'\n\n'
        body+="$(advisory_table "${VULN_ADVISORIES[$pkg@$ver]:-}")"$'\n\n'
        body+="<details>"$'\n'"<summary>📁 Affected files</summary>"$'\n\n'
        while IFS= read -r file; do
            [ -n "$file" ] && body+="- \`${file}\`"$'\n'
        done <<< "${ISSUE_VERSION_FILES[$repo|$pkg|$ver]}"
        body+=$'\n'"</details>"$'\n\n'
    done <<< "$versions"
    body+="### ✅ Recommendations"$'\n\n'
    body+="1. **Update the package** to the latest patched version:"$'\n'"   \`\`\`bash"$'\n'
    body+="$(fix_commands_for_eco "$eco" "$name" "   ")"$'\n'"   \`\`\`"$'\n\n'
    body+="2. **Check for breaking changes** before updating major versions"$'\n\n'
    body+="3. **Run a security audit** after updating:"$'\n'"   \`\`\`bash"$'\n'
    body+="   $(verify_command_for_eco "$eco")"$'\n'"   \`\`\`"$'\n\n'
    body+="4. **Review the advisories** linked above for specific remediation steps"$'\n\n'
    body+="---"$'\n\n'"*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"
    printf '%s' "$body"
}

# One issue per vulnerable package, in the repository that uses it.
create_package_issues() {
    local repo pkg versions title open_titles created=0 total=0 status
    group_findings_for_issues
    for repo in "${ISSUE_REPO_LIST[@]}"; do
        open_titles=$(open_issue_titles "$repo")
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue
            total=$((total + 1))
            versions="${ISSUE_PKG_VERSIONS[$repo|$pkg]}"
            package_advisory_stats "$pkg" "$versions"
            severity_label "$ADV_MAX_RANK"
            title="${SEV_EMOJI} Security: ${ADV_TOTAL} vulnerabilit$([ "$ADV_TOTAL" -eq 1 ] && echo y || echo ies) in \`${pkg#*:}\`"
            [ "${pkg%%:*}" = npm ] || title+=" (${pkg%%:*})"
            [ "$ADV_MAX_RANK" -eq 0 ] || title+=" [${SEV_LABEL}]"
            echo -e "${BLUE}📦 ${pkg#*:}${NC} (${ADV_TOTAL} vulnerability/ies) → ${repo}"
            status=0
            create_issue_once "$repo" "$title" "$(package_issue_body "$repo" "$pkg" "$versions")" "$open_titles" || status=$?
            [ "$status" -ne 0 ] || created=$((created + 1))
            sleep 1  # Rate limiting
            echo ""
        done <<< "${ISSUE_REPO_PKGS[$repo]}"
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✅ Created ${created} issue(s) for ${total} package(s)${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# One consolidated report per repository.
create_consolidated_issues() {
    local repo pkg versions ver file title body details ecos rank status
    local total pkg_count open_titles
    local -a counts
    group_findings_for_issues
    for repo in "${ISSUE_REPO_LIST[@]}"; do
        total=0 pkg_count=0 details="" ecos=""
        counts=(0 0 0 0 0)
        local max_rank=0
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue
            pkg_count=$((pkg_count + 1))
            versions="${ISSUE_PKG_VERSIONS[$repo|$pkg]}"
            package_advisory_stats "$pkg" "$versions"
            total=$((total + ADV_TOTAL))
            for rank in 0 1 2 3 4; do counts[rank]=$(( counts[rank] + ADV_SEV_COUNTS[rank] )); done
            [ "$ADV_MAX_RANK" -le "$max_rank" ] || max_rank=$ADV_MAX_RANK
            case " $ecos " in *" ${pkg%%:*} "*) ;; *) ecos+=" ${pkg%%:*}" ;; esac
            severity_label "$ADV_MAX_RANK"
            details+="<details>"$'\n'"<summary>${SEV_EMOJI} <strong>${pkg#*:}</strong> (${pkg%%:*}, ${ADV_TOTAL} vulnerabilities)</summary>"$'\n\n'
            while IFS= read -r ver; do
                [ -n "$ver" ] || continue
                details+="**Version \`${ver}\`**"$'\n\n'"$(advisory_table "${VULN_ADVISORIES[$pkg@$ver]:-}")"$'\n\n'
                while IFS= read -r file; do
                    [ -n "$file" ] && details+="- \`${file}\`"$'\n'
                done <<< "${ISSUE_VERSION_FILES[$repo|$pkg|$ver]}"
                details+=$'\n'
            done <<< "$versions"
            details+="</details>"$'\n\n'
        done <<< "${ISSUE_REPO_PKGS[$repo]}"

        severity_label "$max_rank"
        title="${SEV_EMOJI} Security Report: ${total} vulnerabilities in ${pkg_count} packages [${SEV_LABEL}]"
        ADV_SEV_COUNTS=("${counts[@]}")
        body="## 🔒 Security Vulnerability Report"$'\n\n'
        body+="This issue contains a consolidated report of all security vulnerabilities detected in this repository."$'\n\n'
        body+="### 📊 Global Summary"$'\n\n'"| Metric | Count |"$'\n'"|--------|-------|"$'\n'
        body+="| **Total Vulnerabilities** | ${total} |"$'\n'"| **Affected Packages** | ${pkg_count} |"$'\n'
        body+="$(severity_summary_rows)"$'\n\n'"---"$'\n\n'"### 📦 Vulnerable Packages"$'\n\n'"$details"
        body+="---"$'\n\n'"### ✅ Recommended Actions"$'\n\n'
        body+="1. **Review each vulnerability** using the advisory links above."$'\n'
        body+="2. **Update the affected packages** to their latest patched versions. Commands per detected ecosystem:"$'\n\n'
        local eco
        for eco in $ecos; do
            body+="#### $(eco_display_name "$eco")"$'\n\n'"\`\`\`bash"$'\n'
            body+="$(fix_commands_for_eco "$eco" "<package-name>")"$'\n'"\`\`\`"$'\n\n'
            body+="Verify: \`$(verify_command_for_eco "$eco")\`"$'\n\n'
        done
        body+="---"$'\n\n'"*🤖 Generated by [package-checker.sh](https://github.com/maxgfr/package-checker.sh)*"

        echo -e "${BLUE}Creating consolidated security report on ${repo}...${NC}"
        open_titles=$(open_issue_titles "$repo")
        status=0
        create_issue_once "$repo" "$title" "$body" "$open_titles" || status=$?
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        case "$status" in
            0) echo -e "${GREEN}✅ Created 1 consolidated issue with ${total} vulnerabilities${NC}" ;;
            2) ;;
            *) echo -e "${RED}❌ Failed to create consolidated issue${NC}" ;;
        esac
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    done
}
