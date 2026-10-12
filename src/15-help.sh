
# ============================================================================
# End of JSON Parser Functions
# ============================================================================

# Show version information
show_version() {
    echo "package-checker.sh version $VERSION"
    echo ""
    echo "Scan project dependencies (npm, PyPI, Go, Maven, Cargo, RubyGems, Composer, NuGet,"
    echo "Pub, Hex, Swift, GitHub Actions) for known vulnerable versions."
    echo "Repository: https://github.com/maxgfr/package-checker.sh"
    exit 0
}

# Help message
show_help() {
    cat << EOF
Usage: $0 [PATH] [OPTIONS]

Scan project dependencies (npm, PyPI, Go, Maven, Cargo, RubyGems, Composer, NuGet,
Pub, Hex, Swift, GitHub Actions) for known vulnerable versions, using the built-in
GHSA/OSV feeds or your own data sources.

ARGUMENTS:
    PATH                    Directory to scan (default: current directory)

OPTIONS:
    -h, --help              Show this help message
    --help-ai               Show AI help menu
    --help-ai prompt        Output the AI system prompt (prompt.md)
    --help-ai doc           Output the full AI guide (docs/ai-guide.md)
    -v, --version           Show version information
    -s, --source SOURCE     Data source path or URL (can be used multiple times)
    --default-source-ghsa   Use default GHSA source (script dir, brew, /app/data/, ./data/, then GitHub)
    --default-source-osv    Use default OSV source (script dir, brew, /app/data/, ./data/, then GitHub)
    --default-source-ghsa-osv        Use both default GHSA and OSV sources (recommended)
    -f, --format FORMAT     Format of the preceding -s source: json, csv, purl, sarif,
                            sbom-cyclonedx or trivy-json (default: auto-detected from
                            the file extension, json when unknown)
    -c, --config FILE       Path to configuration file (default: .package-checker.config.json);
                            its options always apply, its sources only when no source
                            is given on the command line
    --no-config             Skip the default configuration file
    --csv-columns COLS      CSV columns of the preceding -s source (e.g., "1,2" or "name,versions")
    --package-name NAME     Check vulnerability for a specific package name
    --package-version VER   Check specific version (requires --package-name)
    --ecosystem ECO         Ecosystem for --package-name (default: npm). One of:
                            npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions
    --export-json [FILE]    Export results to JSON (FILE optional, default: vulnerabilities.json)
    --export-csv [FILE]     Export results to CSV (FILE optional, default: vulnerabilities.csv)
    --github-org ORG        GitHub organization to fetch package.json files from
    --github-repo REPO      GitHub repository to fetch package.json files from (format: owner/repo)
    --github-token TOKEN    GitHub personal access token (or use GITHUB_TOKEN env var)
    --github-output DIR     Output directory for fetched packages (default: ./packages)
    --github-only           Only fetch packages from GitHub, don't analyze local files
    --create-multiple-issues Create one GitHub issue per vulnerable package (requires --github-token)
    --create-single-issue   Create a single GitHub issue with all vulnerabilities (requires --github-token)
    --fetch-all DIR         Fetch GHSA + OSV feeds for ALL ecosystems to DIR (default: data)
    --fetch-osv [ECOS]      Fetch OSV feeds; optional comma list of ecosystems (default: all)
    --fetch-ghsa [ECOS]     Fetch GHSA feeds (single clone); optional comma list (default: all)
    --only-package-json     Scan only package.json files (skip lockfiles)
    --only-lockfiles        Scan only lockfiles (skip package.json files)
    --lockfile-types TYPES  Comma-separated list of lockfile types to scan
                            (npm, yarn, pnpm, bun, deno, rust, go, python, ruby, php,
                            maven, nuget, dart, hex, swift, actions). "actions" scans
                            GitHub Actions workflow files (.github/workflows/*.yml).
                            Example: --lockfile-types yarn,npm
    --ecosystems ECOS       Comma-separated ecosystems to load default feeds for,
                            overriding auto-detection. Accepts lockfile-type aliases
                            (npm, yarn, pnpm, bun, deno, rust, go, python, ruby, php,
                            maven, nuget, dart, hex, swift, actions) or purl types
                            (npm, pypi, golang, cargo, githubactions, ...).
                            Example: --ecosystems npm

EXIT CODES:
    0   No vulnerable package found
    1   Vulnerable packages found
    2   Error: invalid usage, unreadable or empty data source, failed scan

EXAMPLES:
    # Scan current directory with default sources (recommended)
    $0 --default-source-ghsa-osv

    # Scan specific directory
    $0 ./my-project --default-source-osv
    $0 /absolute/path/to/project --default-source-ghsa-osv

    # Use configuration file
    $0 --config .package-checker.config.json

    # Use custom source (-f/--csv-columns qualify the -s right before them)
    $0 --source https://example.com/vulns.json
    $0 --source ./vulns.csv -f csv --csv-columns "name,versions"

    # GitHub organization scan
    $0 --github-org myorg --github-token ghp_xxxx --default-source-ghsa-osv

    # Check specific package
    $0 --package-name express --package-version 4.17.1

    # Fetch vulnerability feeds (all ecosystems)
    $0 --fetch-all data

    # Fetch feeds for specific ecosystems only
    $0 --fetch-osv pypi,golang
    $0 --fetch-ghsa cargo

    # Scan only lockfiles in specific directory
    $0 ./subfolder --only-lockfiles --lockfile-types yarn,npm

For configuration file format, use: $0 --help format
EOF
    exit 0
}

# Show configuration format help
show_format_help() {
    cat << 'EOF'
CONFIGURATION FILE FORMAT (.package-checker.config.json):
{
  "sources": [
    {
      "source": "https://example.com/vulns.json",
      "format": "json",
      "name": "My Vulnerability List"
    },
    {
      "source": "https://example.com/vulns.csv",
      "format": "csv",
      "columns": "name,versions",
      "name": "CSV Vulnerabilities"
    }
  ],
  "github": {
    "org": "my-organization",
    "repo": "owner/repo",
    "token": "ghp_xxxx",
    "output": "./packages"
  },
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git"],
    "dependency_types": ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
  }
}

DATA FORMATS:

JSON format (object with package names as keys):
{
  "package-name": {
    "versions": ["1.0.0", "2.0.0"]
  }
}

CSV format (default columns: package,version; the first line is a header
unless its version field looks like a version or a range):
name,versions
package-name,1.0.0
package-name,2.0.0
another-package,">=3.0.0 <3.2.1"

CSV format with custom columns:
name,versions,sources
express,4.16.0,"datadog, helixguard"
lodash,4.17.19,"koi, reversinglabs"

Use --csv-columns to specify which columns to use:
--csv-columns "1,2"     # Use columns 1 and 2 (name, versions)
--csv-columns "name,versions"  # Use column names
EOF
    exit 0
}

# GitHub raw base URL for AI docs
GITHUB_RAW_BASE="https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main"

# Resolve an AI doc file: try local paths first, then fetch from GitHub
# Usage: resolve_ai_doc <relative-path>
# Output: file content to stdout
resolve_ai_doc() {
    local file_path="$1"
    local script_dir=""

    # Try to find the script's own directory
    if [ -n "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi

    # 1. Local relative to script location
    if [ -n "$script_dir" ] && [ -f "$script_dir/$file_path" ]; then
        cat "$script_dir/$file_path"
        return 0
    fi

    # 2. Local relative to cwd
    if [ -f "./$file_path" ]; then
        cat "./$file_path"
        return 0
    fi

    # 3. Homebrew prefix
    local brew_prefix=""
    if command -v brew &> /dev/null; then
        brew_prefix="$(brew --prefix 2>/dev/null)/share/package-checker"
        if [ -f "$brew_prefix/$file_path" ]; then
            cat "$brew_prefix/$file_path"
            return 0
        fi
    fi

    # 4. Docker path
    if [ -f "/app/$file_path" ]; then
        cat "/app/$file_path"
        return 0
    fi

    # 5. Fetch from GitHub
    local url="${GITHUB_RAW_BASE}/${file_path}"
    local content
    if content=$(curl -fsSL "$url" 2>/dev/null) && [ -n "$content" ]; then
        echo "$content"
        return 0
    fi

    return 1
}

# Show AI help menu or subcommand
show_ai_help() {
    local subcommand="${1:-}"

    case "$subcommand" in
        prompt)
            echo -e "${BLUE}package-checker.sh — AI System Prompt${NC}"
            echo -e "${BLUE}======================================${NC}"
            echo ""
            echo -e "${YELLOW}Source: ${GITHUB_RAW_BASE}/prompt.md${NC}"
            echo ""
            local content
            if content=$(resolve_ai_doc "prompt.md"); then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load prompt.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/prompt.md"
                exit "$EXIT_ERROR"
            fi
            ;;
        doc)
            echo -e "${BLUE}package-checker.sh — AI Guide (Full Reference)${NC}"
            echo -e "${BLUE}================================================${NC}"
            echo ""
            echo -e "${YELLOW}Source: ${GITHUB_RAW_BASE}/docs/ai-guide.md${NC}"
            echo ""
            local content
            if content=$(resolve_ai_doc "docs/ai-guide.md"); then
                echo "$content"
            else
                echo -e "${RED}❌ Error: Could not load docs/ai-guide.md${NC}"
                echo ""
                echo "Try one of:"
                echo "  - Clone the repo and run locally"
                echo "  - curl -fsSL ${GITHUB_RAW_BASE}/docs/ai-guide.md"
                exit "$EXIT_ERROR"
            fi
            ;;
        *)
            cat << EOF
AI-Assisted Usage for package-checker.sh
=========================================

Use these commands to get AI-ready documentation:

  $(basename "$0") --help-ai prompt    Output the system prompt (prompt.md)
                                  Paste this into any AI assistant as context.

  $(basename "$0") --help-ai doc       Output the full AI guide (docs/ai-guide.md)
                                  Complete schemas, validation rules, and recipes.

One-liner to inject into an AI conversation:

  $(basename "$0") --help-ai prompt | pbcopy       # macOS: copy to clipboard
  $(basename "$0") --help-ai prompt | xclip        # Linux: copy to clipboard
  $(basename "$0") --help-ai prompt > context.md   # Save to file and attach

GitHub URLs (always up-to-date):

  Prompt:  ${GITHUB_RAW_BASE}/prompt.md
  Guide:   ${GITHUB_RAW_BASE}/docs/ai-guide.md

EOF
            ;;
    esac
    exit 0
}

