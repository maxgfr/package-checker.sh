# GitHub API functions
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_ORG="${GITHUB_ORG:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_OUTPUT_DIR="${GITHUB_OUTPUT_DIR:-./packages}"
GITHUB_ONLY=false
GITHUB_RATE_LIMIT_DELAY=2
CREATE_GITHUB_ISSUE=false
CREATE_SINGLE_ISSUE=false

# Make a GitHub API request with automatic retry on rate limit
github_request() {
    local url="$1"
    local max_retries=3
    local retry_delay=60
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        local response
        local http_code
        
        response=$(curl -sS -w "\n%{http_code}" \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "Accept: application/vnd.github.v3+json" \
            -H "User-Agent: package-checker-script" \
            "$url")
        
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | sed '$d')
        
        if [ "$http_code" = "200" ]; then
            echo "$response"
            return 0
        fi
        
        # Handle rate limiting (403 or 429)
        if [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
            if [ $attempt -lt $max_retries ]; then
                # Check for Retry-After header or rate limit reset time
                local wait_time=$retry_delay
                if echo "$response" | grep -q "rate limit"; then
                    echo -e "${YELLOW}⚠️  Rate limit hit, waiting ${wait_time}s before retry ($attempt/$max_retries)...${NC}" >&2
                    sleep $wait_time
                    attempt=$((attempt + 1))
                    continue
                fi
            fi
        fi
        
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
    
    # Get the default branch first
    local repo_info
    repo_info=$(github_request "https://api.github.com/repos/${repo_full_name}") || return 1
    local default_branch=$(json_get_value "$repo_info" "default_branch")
    
    # Get the full tree recursively
    local tree_url="https://api.github.com/repos/${repo_full_name}/git/trees/${default_branch}?recursive=1"
    local tree_response
    tree_response=$(github_request "$tree_url") || return 1
    
    # OPTIMIZED: Use grep/sed to extract paths directly instead of slow JSON parsing
    # Extract all "path" values from the tree response and filter for target files
    # This is MUCH faster than iterating with json_array_get for large trees
    local target_files
    target_files=$(echo "$tree_response" | \
        grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"$//' | \
        grep -v 'node_modules' | \
        grep -E '(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|deno\.lock)$')
    
    if [ -z "$target_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Count files by type
    local pkg_count=$(echo "$target_files" | grep -c "package.json" || echo "0")
    local lock_count=$(echo "$target_files" | grep -v "package.json" | grep -c "." || echo "0")
    echo "   Found $pkg_count package.json file(s) and $lock_count lockfile(s)"
    
    # Create repo directory
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    mkdir -p "$repo_dir"
    
    # Fetch each file
    while IFS= read -r file_path; do
        [ -z "$file_path" ] && continue
        
        local raw_url="https://raw.githubusercontent.com/${repo_full_name}/${default_branch}/${file_path}"
        local file_content
        file_content=$(curl -sS \
            ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            -H "User-Agent: package-checker-script" \
            "$raw_url")
        
        # Save the file
        local full_path="${repo_dir}/${file_path}"
        local dir=$(dirname "$full_path")
        mkdir -p "$dir"
        
        echo "$file_content" > "$full_path"
        
        local file_name=$(basename "$file_path")
        if [ "$file_name" = "package.json" ]; then
            echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
        else
            echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
        fi
    done <<< "$target_files"
}

# Search for package.json and lockfiles in a repository using Search API (requires token)
search_package_json_in_repo() {
    local repo_full_name="$1"
    local repo_name="$2"
    
    echo -e "   ${BLUE}Searching for package.json and lockfiles...${NC}"
    
    # Search for multiple file types
    local all_files=""
    local search_terms=("package.json" "package-lock.json" "npm-shrinkwrap.json" "yarn.lock" "pnpm-lock.yaml" "bun.lock" "deno.lock")
    
    for term in "${search_terms[@]}"; do
        local search_url="https://api.github.com/search/code?q=filename:${term}+repo:${repo_full_name}"
        local search_results
        
        search_results=$(github_request "$search_url") 2>/dev/null || continue
        
        # OPTIMIZED: Extract path and url pairs using grep/sed instead of slow JSON parsing
        # Format: path|url (one per line)
        local file_pairs
        file_pairs=$(echo "$search_results" | tr '\n' ' ' | \
            grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"[^}]*"url"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            sed 's/"path"[[:space:]]*:[[:space:]]*"//;s/"[^}]*"url"[[:space:]]*:[[:space:]]*"/|/;s/"$//')
        
        if [ -n "$file_pairs" ]; then
            if [ -z "$all_files" ]; then
                all_files="$file_pairs"
            else
                all_files="$all_files"$'\n'"$file_pairs"
            fi
        fi
        
        sleep 1  # Rate limiting between searches
    done
    
    if [ -z "$all_files" ]; then
        echo "   ✗ No package.json or lockfiles found"
        return 0
    fi
    
    # Remove duplicates and count
    all_files=$(echo "$all_files" | sort -u)
    local count=$(echo "$all_files" | wc -l | tr -d ' ')
    echo "   Found $count file(s)"
    
    # Create repo directory
    local repo_dir="${GITHUB_OUTPUT_DIR}/${repo_name}"
    mkdir -p "$repo_dir"
    
    # Fetch each file
    while IFS='|' read -r file_path file_url; do
        [ -z "$file_path" ] && continue
        
        # Get file content
        local content_response
        content_response=$(github_request "$file_url") || continue
        
        local download_url=$(json_get_value "$content_response" "download_url")
        
        if [ -n "$download_url" ] && [ "$download_url" != "null" ]; then
            local file_content
            file_content=$(curl -sS \
                ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
                -H "User-Agent: package-checker-script" \
                "$download_url")
            
            # Save the file
            local full_path="${repo_dir}/${file_path}"
            local dir=$(dirname "$full_path")
            mkdir -p "$dir"
            
            echo "$file_content" > "$full_path"
            
            local file_name=$(basename "$file_path")
            if [ "$file_name" = "package.json" ]; then
                echo -e "   ${GREEN}✓ Saved: ${repo_name}/${file_path}${NC}"
            else
                echo -e "   ${BLUE}✓ Saved: ${repo_name}/${file_path}${NC}"
            fi
        fi
        
        sleep 1  # Rate limiting
    done <<< "$all_files"
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
    response=$(curl -s -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "$json_payload" \
        "https://api.github.com/repos/${repo_full_name}/issues" 2>&1)

    # Check if issue was created successfully
    if echo "$response" | grep -q '"html_url"'; then
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
    
    # Token is required for organization (uses Search API)
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
            
            # Use Tree API instead of Search API (much higher rate limit)
            search_package_json_in_repo_tree "$repo_full_name" "$repo_name"
            
            sleep "$GITHUB_RATE_LIMIT_DELAY"
        done <<< "$repos"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ GitHub packages fetched to: $(realpath "$GITHUB_OUTPUT_DIR")${NC}"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# Check if a version string is a range (contains operators like >=, <=, >, <)
