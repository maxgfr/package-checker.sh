# package-checker.sh

A flexible, lightweight shell script to detect vulnerable npm packages against custom vulnerability databases. Check your Node.js projects for known vulnerable package versions using your own data sources.

## 🚀 Features

- **Custom Data Sources**: Configure your own vulnerability lists (JSON or CSV format)
- **Automatic Format Detection**: Detects JSON/CSV from file extensions
- **Flexible CSV Support**: Handle CSV files with custom columns (by name or index)
- **Version Ranges**: Define vulnerable version ranges (e.g., `>=1.0.0 <2.0.0`) instead of listing all versions
- **Pre-release Detection**: Automatically detects pre-release versions (rc, alpha, beta) of vulnerable versions
- **Local & Remote Files**: Support for both local files and remote URLs
- **Multiple Sources**: Combine multiple vulnerability databases in one scan
- **Multiple Package Managers**: Supports npm, Yarn, pnpm, Bun, and Deno
- **Recursive Scanning**: Finds all lockfiles and package.json files in subdirectories
- **Respects .gitignore**: Automatically excludes ignored files
- **Monorepo-Friendly**: Perfect for projects with multiple packages
- **Flexible Configuration**: Use command-line arguments or configuration files
- **Color-Coded Output**: Easy-to-read results with visual highlighting

## 📋 Prerequisites

- **curl** (required): HTTP client for fetching remote data sources
  - Usually pre-installed on most systems
  - macOS: Pre-installed
  - Ubuntu/Debian: `apt-get install curl`

**Note:** This script has no external dependencies like `jq`. All JSON parsing is done using pure Bash.

## 🎯 Quick Start

### With Configuration File

1. Create a [`.pkgcheck.json`](.pkgcheck.json) file in your project:

```json
{
  "sources": [
    {
      "url": "https://your-domain.com/vulnerabilities.json",
      "name": "Your Vulnerability Database"
    }
  ]
}
```

2. Download and run the script:

```bash
curl -O https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh
chmod +x script.sh
./script.sh
```

### With Custom Data Source

```bash
# Format is automatically detected from file extension
./script.sh --source https://your-domain.com/vulnerabilities.json

# Or with CSV
./script.sh --source https://your-domain.com/vulnerabilities.csv

# You can also specify format explicitly if needed
./script.sh --source https://your-domain.com/vulnerabilities.json --format json
```

### With GitHub Organization

Fetch and analyze all `package.json` files from a GitHub organization:

```bash
# Using command-line options
./script.sh --github-org myorg --github-token ghp_xxxx --source vulns.json

# Using environment variables
GITHUB_ORG=myorg GITHUB_TOKEN=ghp_xxxx ./script.sh --source vulns.json

# Fetch packages only (without vulnerability analysis)
./script.sh --github-org myorg --github-token ghp_xxxx --github-only

# Custom output directory
./script.sh --github-org myorg --github-token ghp_xxxx --github-output ./my-packages --source vulns.json
```

### With GitHub repository (single repo)

Fetch and analyze `package.json` and supported lockfiles from a single GitHub repository.

- For public repositories the script can fetch files without a token using the repository tree (rate-limited).
- For private repositories you must provide a token via `--github-token` or `GITHUB_TOKEN`.

```bash
# Public repository (no token required, but requests are rate-limited):
./script.sh --github-repo owner/repo --source ./my-vulns.json --no-config

# Private repository (token required):
./script.sh --github-repo owner/private-repo --github-token ghp_xxxx --source ./my-vulns.json --no-config

# Save fetched files into a custom output directory and analyze:
./script.sh --github-repo owner/repo --github-output ./packages-from-github --source ./my-vulns.json --no-config
```

### With Configuration File

Create a [`.pkgcheck.json`](.pkgcheck.json) file:

```json
{
  "sources": [
    {
      "url": "https://your-domain.com/vulns.json",
      "name": "Internal Security DB"
    },
    {
      "url": "https://another-source.com/vulns.csv",
      "name": "External Vulnerabilities"
    }
  ]
}
```

**Note**: The `format` field is optional - the script automatically detects the format from the file extension (`.json` or `.csv`).

Then run:

```bash
./script.sh
```

## 📖 Usage

```bash
./script.sh [OPTIONS]

OPTIONS:
    -h, --help              Show help message
    -s, --source SOURCE     Data source path or URL (can be used multiple times)
    -f, --format FORMAT     Data format: json or csv (optional, auto-detected from extension)
    --csv-columns COLS      CSV columns specification (e.g., "1,2" or "package_name,package_versions")
    -c, --config FILE       Path to configuration file
    --no-config             Skip loading configuration file
    --github-org ORG        GitHub organization to fetch package.json files from
    --github-token TOKEN    GitHub personal access token (or use GITHUB_TOKEN env var)
    --github-output DIR     Output directory for fetched packages (default: ./packages)
    --github-only           Only fetch packages from GitHub, don't analyze local files
```

### Examples

#### Multiple Data Sources

```bash
# Format is auto-detected from file extensions
./script.sh \
  --source https://source1.com/vulns.json \
  --source https://source2.com/vulns.csv

# Or specify formats explicitly
./script.sh \
  --source https://source1.com/data --format json \
  --source https://source2.com/data --format csv
```

#### Custom Configuration File

```bash
./script.sh --config ./security/my-vulns-config.json
```

#### Direct Execution (One-liner)

With configuration file:

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

With custom URL:

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://your-domain.com/vulnerabilities.json
```

With multiple sources:

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://example.com/vulns1.json --source https://example.com/vulns2.csv
```

With GitHub Organization (fetch packages from an org and analyze):

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --github-org myorg --github-token "$GITHUB_TOKEN" --source https://example.com/vulns.json
```

With GitHub repository (single repo; public repos can be fetched without a token):

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --github-repo owner/repo --source ./my-vulns.json --no-config
```

#### Real-world Example with Multiple Sources

```bash
# Using multiple security databases in one scan
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- \
  --source https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/refs/heads/main/list.json \
  --source https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv
```

## 📊 Data Source Formats

### JSON Format

The script expects a JSON object where keys are package names and values contain vulnerability information:

```json
{
  "package-name": {
    "vulnerability_version": ["1.0.0", "2.0.0", "2.1.0"]
  },
  "@scope/another-package": {
    "vulnerability_version": ["3.0.0"]
  }
}
```

#### Version Ranges

You can also use version ranges to avoid listing every vulnerable version:

```json
{
  "lodash": {
    "vulnerability_range": [">=4.0.0 <4.17.21"]
  },
  "axios": {
    "vulnerability_version": ["0.21.0", "0.21.1"],
    "vulnerability_range": [">=0.18.0 <0.21.2"]
  },
  "moment": {
    "vulnerability_range": [">=2.0.0 <2.29.4", ">=3.0.0 <3.0.1"]
  }
}
```

**Range operators:**
- `>` : greater than
- `>=` : greater than or equal
- `<` : less than
- `<=` : less than or equal

**Examples:**
- `">=1.0.0 <2.0.0"` - versions from 1.0.0 (inclusive) to 2.0.0 (exclusive)
- `">1.0.0 <=1.5.0"` - versions after 1.0.0 up to and including 1.5.0
- `">=0.0.1"` - all versions from 0.0.1 onwards

**Note:** You can combine `vulnerability_version` (exact versions) and `vulnerability_range` (ranges) for the same package.

### CSV Format

Simple comma-separated format with package name and version:

```csv
package_name,package_versions
express,4.16.0
express,4.16.1
lodash,4.17.19
@scope/scoped-package,1.5.0
```

**Notes:**

- First line is a header (will be ignored if it contains column names)
- Whitespace is automatically trimmed
- Supports scoped packages (`@scope/package`)
- Column headers: `package_name,package_versions`

#### CSV with Custom Columns

The script supports CSV files with more than 2 columns. You can specify which columns to use:

**Specify columns by name:**

```bash
./script.sh --source data.csv --format csv --csv-columns "package_name,package_versions"
```

**Specify columns by index:**

```bash
./script.sh --source data.csv --format csv --csv-columns "1,2"
```

**Example CSV with 3 columns:**

```csv
package_name,package_versions,sources
express,4.16.0,"datadog, helixguard"
lodash,4.17.19,"koi, reversinglabs"
@scope/package,1.2.3,"security-vendor"
```

#### CSV with Version Ranges

CSV files also support version ranges! The script automatically detects if a version string is a range (contains `>=`, `<=`, `>`, or `<`) and handles it appropriately:

```csv
package_name,package_versions,source
next,15.6.0,json-source
next,">=15.0.0 <15.0.5",json-source
next,">=16.0.0 <16.0.7",json-source
lodash,4.17.19,security-db
lodash,">=4.0.0 <4.17.21",security-db
```

**Notes:**
- Version ranges must be quoted if they contain spaces
- Exact versions and ranges can be mixed for the same package
- The script automatically separates them into `vulnerability_version` and `vulnerability_range` internally

**Configuration file example:**

```json
{
  "sources": [
    {
      "url": "my-vulnerabilities.csv",
      "format": "csv",
      "columns": "package_name,package_versions",
      "name": "Custom Vulnerabilities"
    }
  ]
}
```

## ⚙️ Configuration File

Create a [`.pkgcheck.json`](.pkgcheck.json) in your project root:

```json
{
  "sources": [
    {
      "url": "https://example.com/vulnerabilities.json",
      "name": "Company Security Database"
    },
    {
      "url": "https://security.company.com/npm-vulns.json",
      "name": "Internal NPM Vulnerabilities"
    },
    {
      "url": "https://example.com/custom-vulns.csv",
      "name": "Custom Vulnerabilities"
    }
  ]
}
```

**Fields:**

- `url`: Source URL (required)
- `format`: Data format - "json" or "csv" (optional, auto-detected from file extension)
- `columns`: CSV columns specification (optional, for CSV files with custom columns)
- `name`: Human-readable name (optional, for display purposes)

**Format Auto-Detection:**

The script automatically detects the format based on the URL file extension:

- `.json` → JSON format
- `.csv` → CSV format
- Unknown extensions default to JSON format

You can explicitly specify the `format` field if the URL doesn't have a standard extension.

## 🔍 What Gets Scanned

The script analyzes:

### Lockfiles (exact version matching)

- `package-lock.json` (npm)
- `npm-shrinkwrap.json` (npm)
- `yarn.lock` (Yarn v1/v2/v3)
- `pnpm-lock.yaml` (pnpm)
- `bun.lock` (Bun)
- `deno.lock` (Deno)

### package.json Files (dependency checking)

- `dependencies`
- `devDependencies`
- `optionalDependencies`
- `peerDependencies`

All files are found recursively while respecting [`.gitignore`](script.sh:488) rules.

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check for vulnerabilities
        run: |
          curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

### GitLab CI

```yaml
vulnerability-check:
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl
  script:
    - curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

### Custom Configuration in CI

```yaml
- name: Check vulnerabilities with custom source
  run: |
    ./script.sh \
      --source https://company.internal/vulns.json \
      --format json
```

## 🎨 Advanced Usage

### Multiple Sources with Priority

Combine multiple vulnerability databases - the script merges all sources:

```bash
./script.sh \
  --source https://primary-source.com/vulns.json \
  --source https://secondary-source.com/vulns.csv \
  --source https://third-source.com/vulns.json
```

### Custom Config Location

```bash
./script.sh --config ./security/vulnerability-sources.json
```

### Skip Config File

```bash
./script.sh --no-config --source https://direct-source.com/vulns.json
```

### Using Local Files

```bash
# Use local CSV file with custom columns
./script.sh --source ./vulnerabilities.csv --format csv --csv-columns "package_name,package_versions"

# Use local JSON file
./script.sh --source ./vulnerabilities.json --format json
```

## 🛠️ Creating Your Own Vulnerability Database

### JSON Format

Host a JSON file with this structure (see [`example-vulnerabilities.json`](example-vulnerabilities.json)):

```json
{
  "express": {
    "vulnerability_version": ["4.16.0", "4.16.1", "4.17.0"]
  },
  "lodash": {
    "vulnerability_range": [">=4.17.0 <4.17.21"]
  },
  "axios": {
    "vulnerability_version": ["0.21.0", "0.21.1"],
    "vulnerability_range": [">=0.18.0 <0.21.2"]
  },
  "@types/node": {
    "vulnerability_version": ["14.0.0", "14.0.1"]
  },
  "moment": {
    "vulnerability_range": [">=2.0.0 <2.29.4"]
  }
}
```

**Available fields:**
- `vulnerability_version`: Array of exact vulnerable versions
- `vulnerability_range`: Array of version ranges (e.g., `">=1.0.0 <2.0.0"`)

You can use both fields together for maximum flexibility.

### CSV Format

Create a CSV file (see [`example-vulnerabilities.csv`](example-vulnerabilities.csv)):

```csv
package_name,package_versions
express,4.16.0
express,4.16.1
express,4.17.0
lodash,4.17.19
lodash,4.17.20
lodash,4.17.21
@types/node,14.0.0
@types/node,14.0.1
```

Then host it and use:

```bash
# Format is automatically detected from .csv extension
./script.sh --source https://your-domain.com/vulnerabilities.csv

# Or test locally with example files
./script.sh --source file://$(pwd)/example-vulnerabilities.json
./script.sh --source file://$(pwd)/example-vulnerabilities.csv
```

## 📚 Use Cases

- **Security Teams**: Maintain internal vulnerability databases
- **Compliance**: Check against company-specific security policies
- **Incident Response**: Quickly scan projects during security incidents
- **Continuous Monitoring**: Integrate into CI/CD for automated checks
- **Supply Chain Security**: Track vulnerable dependencies across multiple projects
- **Custom Threat Intelligence**: Use proprietary vulnerability data

## 📝 License

MIT License - see the [LICENSE](LICENSE) file for details.
