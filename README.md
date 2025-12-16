# package-checker.sh

A flexible, lightweight shell script to detect vulnerable npm packages. Includes built-in GHSA and OSV vulnerability feeds with 200,000+ vulnerabilities, or use your own custom databases.

## 📦 Overview

**package-checker.sh** scans your JavaScript/TypeScript projects for vulnerable dependencies. Works with npm, Yarn, pnpm, Bun, and Deno projects.

### Key Features

- **Built-in Vulnerability Feeds**: GHSA and OSV feeds with 200,000+ npm vulnerabilities included (auto-updated every 12 hours)
- **Docker Images Available**: Full image (~43MB with feeds) or lightweight (~27MB)
- **Custom Data Sources**: Add your own JSON, CSV, or PURL vulnerability lists
- **Scanner Integration**: Consume SARIF, SBOM, or Trivy JSON from external tools
- **Version Ranges**: Define ranges like `>=1.0.0 <2.0.0` instead of listing every version
- **Multiple Package Managers**: Full support for npm, Yarn (Classic & Berry/v2+), pnpm, Bun, and Deno
- **GitHub Integration**: Scan entire organizations or individual repositories directly from GitHub
- **Zero Dependencies**: Only requires `bash`, `awk`, and `curl`
- **Flexible Configuration**: Use CLI arguments or `.package-checker.config.json` file

### Prerequisites

- **bash** — Shell interpreter
- **awk** (gawk or mawk) — Usually pre-installed
- **curl** — For remote sources and GitHub API
- Or use Docker images (no installation required)

---

## 🚀 Getting Started

### Option 1: One-Click Install & Run (Quickest)

Run directly from the web with your own vulnerability data:

```bash
# Run with remote vulnerability source
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh | bash -s -- --source https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl

# Or with local source file
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh | bash -s -- --source ./vulns.json
```

### Option 2: Using Docker (Recommended)

The easiest way to get started with built-in vulnerability feeds:

```bash
# Scan with built-in GHSA feed (no setup required!)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --source /app/data/ghsa.purl

# Or use both GHSA and OSV feeds for comprehensive coverage
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest \
  --source /app/data/ghsa.purl \
  --source /app/data/osv.purl

# Use with your own data files
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --source my-vulns.json
```

### Option 3: Clone Repository

Get the script and built-in vulnerability feeds:

```bash
# Clone the repository
git clone https://github.com/maxgfr/package-checker.sh.git
cp package-checker.sh/script.sh .
chmod +x script.sh

# Scan with built-in GHSA feed
./script.sh --source ./package-checker.sh/data/ghsa.purl

# Or use both feeds
./script.sh --source ./package-checker.sh/data/ghsa.purl --source ./package-checker.sh/data/osv.purl
```

### Option 4: Download Script Only

Download just the script (bring your own vulnerability data):

```bash
curl -O https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh
chmod +x script.sh

# Use with custom vulnerability source
./script.sh --source https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl
```

### Basic Usage Examples

```bash
# Use built-in GHSA feed (200,000+ vulnerabilities)
./script.sh --source data/ghsa.purl

# Check specific package version
./script.sh --package-name express --package-version 4.17.1

# Check with version ranges
./script.sh  --package-name lodash --package-version '^4.17.0'

# Scan with custom vulnerability file
./script.sh --source custom-vulns.json

# Multiple sources (built-in + custom)
./script.sh --source data/ghsa.purl --source custom-vulns.csv

# Scan with SARIF format (from Trivy, Semgrep, etc.)
./script.sh --source vulnerabilities.sarif

# Scan with SBOM CycloneDX format
./script.sh --source sbom.cdx.json

# Use configuration file
./script.sh --config .package-checker.config.json

# Scan GitHub organization
./script.sh --source data/ghsa.purl --github-org myorg --github-token $GITHUB_TOKEN
```

### Command-Line Options

```text
-h, --help                Show help message
-s, --source SOURCE       Vulnerability source (repeatable for multiple sources)
-f, --format FORMAT       Data format: json, csv, purl, sarif, sbom-cyclonedx, or trivy-json (auto-detected from extension)
--csv-columns COLS        CSV columns: "name,versions" or "1,2"
--package-name NAME       Check vulnerability for a specific package name
--package-version VER     Check specific version (requires --package-name)
-c, --config FILE         Path to configuration file
--no-config               Skip loading configuration file
--export-json FILE        Export vulnerability results to JSON format (default: vulnerabilities.json)
--export-csv FILE         Export vulnerability results to CSV format (default: vulnerabilities.csv)
--github-org ORG          GitHub organization to scan
--github-repo owner/repo  Single GitHub repository to scan
--github-token TOKEN      GitHub token (or use GITHUB_TOKEN env var)
--github-output DIR       Output directory for fetched files (default: ./packages)
--github-only             Only fetch from GitHub, skip local analysis
--create-issue            Create GitHub issues for repositories with vulnerabilities (requires --github-token)
--fetch-all DIR           Fetch all vulnerability feeds (osv.purl, ghsa.purl) to specified directory
--fetch-osv FILE          Fetch OSV vulnerability feed to specified file
--fetch-ghsa FILE         Fetch GHSA vulnerability feed to specified file
```

---

## ⚙️ Configuration & Data Formats

### Configuration File

Create a `.package-checker.config.json` in your project root:

```json
{
  "sources": [
    {
      "source": "https://example.com/vulnerabilities.json",
      "name": "Company Security Database"
    },
    {
      "source": "https://example.com/vulnerabilities.csv",
      "format": "csv",
      "columns": "name,versions",
      "name": "Custom Vulnerabilities"
    },
    {
      "source": "https://example.com/vulnerabilities.purl",
      "format": "purl",
      "name": "PURL Vulnerability List"
    }
  ],
  "github": {
    "org": "my-organization",
    "repo": "owner/repo",
    "token": "",
    "output": "./packages"
  },
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git", "dist"],
    "dependency_types": ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
  }
}
```

### JSON Format

Example vulnerability database ([`example-vulnerabilities.json`](example-vulnerabilities.json)):

```json
{
  "express": {
    "versions": ["4.16.0", "4.16.1"]
  },
  "lodash": {
    "versions_range": [">=4.17.0 <4.17.21"]
  },
  "axios": {
    "versions": ["0.21.0"],
    "versions_range": [">=0.18.0 <0.21.2"]
  }
}
```

**Fields:**
- `versions`: Array of exact vulnerable versions
- `versions_range`: Array of version ranges with operators (`>=`, `>`, `<`, `<=`, `~`, `^`)

### CSV Format

Example vulnerability database ([`example-vulnerabilities.csv`](example-vulnerabilities.csv)):

```csv
name,versions
express,4.16.0
express,4.16.1
lodash,">=4.17.0 <4.17.21"
axios,0.21.0
```

**Notes:**
- First line is a header (automatically detected)
- Version ranges must be quoted if they contain spaces
- Supports custom columns via `--csv-columns` option or config file

### PURL Format

PURL (Package URL) is a standardized format for identifying software packages. Example vulnerability database:

```text
# Critical vulnerabilities
pkg:npm/lodash@4.17.20
pkg:npm/minimist@1.2.5
pkg:npm/axios@0.21.0

# Scoped packages
pkg:npm/@babel/traverse@7.23.0

# Version ranges
pkg:npm/express@>=4.0.0 <4.17.21
pkg:npm/react@>=16.0.0 <16.14.0
pkg:npm/ws@>=7.0.0 <7.4.6
```

**Format:** `pkg:type/namespace/name@version`

**Notes:**

- One package per line
- Supports exact versions and version ranges
- Empty lines and lines starting with `#` are ignored (comments)
- Package name is extracted from the last component of the path
- Auto-detected for `.purl` and `.txt` file extensions

For more details, see the [data-formats documentation](docs/data-formats.md).

### Using Vulnerability Feeds

**📦 Local data sources included**: This repository includes pre-generated vulnerability feeds that are automatically updated every 12 hours via GitHub Actions. Use them directly without fetching anything!

**Available local feeds:**

- `data/osv.purl` - ~206,000+ npm vulnerabilities from OSV
- `data/ghsa.purl` - ~5,000+ npm vulnerabilities from GHSA

**Quick start with local feeds:**

```bash
# Clone the repository to get up-to-date local feeds
git clone https://github.com/maxgfr/package-checker.sh.git
cd package-checker.sh
chmod +x script.sh

# Scan your project with local GHSA feed (no fetching needed!)
./script.sh --source data/ghsa.purl

# Use both local feeds for comprehensive scanning
./script.sh --source data/osv.purl --source data/ghsa.purl

# Check a specific package against local GHSA data
./script.sh --package-name lodash --package-version 4.17.20 --source data/ghsa.purl
```

**Fetch fresh feeds (optional):**

If you need the absolute latest data, you can fetch feeds yourself:

```bash
# Fetch all feeds (OSV + GHSA)
./script.sh --fetch-all data

# Fetch only OSV feed
./script.sh --fetch-osv data/osv.purl

# Fetch only GHSA feed
./script.sh --fetch-ghsa data/ghsa.purl
```

**Real-world workflow:**

```bash
# 1. Use the local feeds directly and scan your project (recommended - already up-to-date!)
./script.sh --source data/ghsa.purl

# 2. Or fetch fresh feeds if you need the absolute latest data
./script.sh --fetch-all data

# 3. Scan a GitHub organization
./script.sh --github-org your-org --source data/ghsa.purl --github-token $GITHUB_TOKEN

# 4. Use both feeds for comprehensive scanning
./script.sh --source data/osv.purl --source data/ghsa.purl
```

The feeds are in PURL format with metadata (severity, GHSA ID, CVE, source) as query parameters. See the [vulnerability feeds documentation](docs/vulnerability-feeds.md) for detailed information.

### SARIF Format

SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tool outputs. It's supported by many security tools including Trivy, Semgrep, CodeQL, and others.

**Generating SARIF with Trivy:**

```bash
# Scan filesystem and output SARIF
trivy fs --format sarif --output vulnerabilities.sarif .

# Use with package-checker
./script.sh --source vulnerabilities.sarif --format sarif
```

**Notes:**

- Auto-detected for `.sarif` file extension
- Extracts package names and installed versions from SARIF results
- Works with SARIF 2.1.0 format
- Compatible with GitHub Code Scanning uploads

### SBOM CycloneDX Format

SBOM (Software Bill of Materials) in CycloneDX format provides a complete inventory of components and their vulnerabilities. This format is generated by tools like Trivy, Syft, and others.

**Generating SBOM with Trivy:**

```bash
# Generate SBOM in CycloneDX JSON format
trivy fs --format cyclonedx --output sbom.cdx.json .

# Or use the specific CycloneDX format
trivy sbom --format cyclonedx-json --output sbom.cdx.json .

# Use with package-checker
./script.sh --source sbom.cdx.json --format sbom-cyclonedx
```

**Notes:**

- Auto-detected for `.sbom`, `.cdx`, `.sbom.json`, `.cdx.json`, and `.sbom.cdx.json` file extensions
- Extracts vulnerabilities from the `vulnerabilities` array
- Parses PURL (Package URL) references to identify packages
- Supports CycloneDX 1.4+ specification

### Trivy JSON Format

Trivy's native JSON output format contains detailed vulnerability information along with package metadata.

**Generating Trivy JSON:**

```bash
# Scan filesystem with JSON output
trivy fs --format json --output trivy-report.json .

# Scan container image
trivy image --format json --output trivy-report.json nginx:latest

# Use with package-checker
./script.sh --source trivy-report.json --format trivy-json
```

**Alternative Tools:**

You can use any tool that generates vulnerability reports in these formats:

```bash
# Using grype for SBOM
grype dir:. -o cyclonedx-json > sbom.json
./script.sh --source sbom.json --format sbom-cyclonedx

# Using osv-scanner with SARIF
osv-scanner --format sarif -r . > vulnerabilities.sarif
./script.sh --source vulnerabilities.sarif --format sarif

# Using syft for SBOM
syft . -o cyclonedx-json > sbom.json
./script.sh --source sbom.json --format sbom-cyclonedx
```

**Notes:**

- Auto-detected for `.trivy.json` and `.trivy` file extensions
- Extracts package names and installed versions from Trivy's `Results` array
- Works with both filesystem and container image scans
- Compatible with all Trivy vulnerability databases

### What Gets Scanned

**Lockfiles** (exact version matching):
- `package-lock.json`, `npm-shrinkwrap.json` (npm)
- `yarn.lock` (Yarn Classic & Yarn Berry/v2+)
- `pnpm-lock.yaml` (pnpm)
- `bun.lock` (Bun)
- `deno.lock` (Deno)

**package.json** (dependency checking):
- `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`

### Exporting Results

You can export scan results to JSON or CSV format for further analysis, reporting, or integration with other tools.

**Export to JSON:**
```bash
# Export with default filename (vulnerabilities.json)
./script.sh --source vulns.json --export-json

# Export with custom filename
./script.sh --source vulns.json --export-json results.json
```

**Export to CSV:**
```bash
# Export with default filename (vulnerabilities.csv)
./script.sh --source vulns.json --export-csv

# Export with custom filename
./script.sh --source vulns.json --export-csv results.csv
```

**Export both formats:**
```bash
./script.sh --source vulns.json --export-json output.json --export-csv output.csv
```

**JSON Export Format:**

The JSON export includes detailed vulnerability information with metadata:

```json
{
  "vulnerabilities": [
    {
      "package": "express@4.16.0",
      "file": "./package-lock.json",
      "severity": "medium",
      "ghsa": "GHSA-rv95-896h-c2vc",
      "cve": "CVE-2022-24999",
      "source": "ghsa"
    }
  ],
  "summary": {
    "total_unique_vulnerabilities": 5,
    "total_occurrences": 12
  }
}
```

**CSV Export Format:**

The CSV export includes the same metadata in a tabular format:

```csv
package,file,severity,ghsa,cve,source
express@4.16.0,./package-lock.json,medium,GHSA-rv95-896h-c2vc,CVE-2022-24999,ghsa
lodash@4.17.20,./package-lock.json,high,GHSA-p6mc-m468-83gw,CVE-2020-8203,ghsa
```

**Notes:**

- Exports only include packages where vulnerabilities were found
- Metadata fields (severity, GHSA, CVE, source) are included when available in the vulnerability database
- See the [Data Formats documentation](docs/data-formats.md) for details on adding metadata to your vulnerability sources

### GitHub Integration

**Scan an entire organization:**
```bash
./script.sh --github-org myorg --github-token ghp_xxx --source vulns.json
```

**Scan a single repository:**
```bash
# Public repo (no token needed)
./script.sh --github-repo owner/repo --source vulns.json

# Private repo (token required)
./script.sh --github-repo owner/private-repo --github-token ghp_xxx --source vulns.json
```

**Fetch only (no analysis):**
```bash
./script.sh --github-org myorg --github-token ghp_xxx --github-only --github-output ./packages
```

**Automatically create GitHub issues for vulnerabilities:**
```bash
# Scan organization and create issues on repositories with vulnerabilities
./script.sh --github-org myorg --github-token ghp_xxx --source vulns.json --create-issue

# Scan single repository and create issue if vulnerabilities found
./script.sh --github-repo owner/repo --github-token ghp_xxx --source vulns.json --create-issue
```

When using `--create-issue`, the tool will automatically create GitHub issues on repositories where vulnerabilities are detected. Each issue includes:

- Package name and version
- Vulnerability source
- Recommendations for remediation
- Automatic labeling with `security` and `vulnerability` tags

**Note:** The `--create-issue` flag requires a GitHub token with `repo` scope to create issues.

### Direct Package Lookup

You can check if a specific package or version is vulnerable **without needing a data source or scanning a project**:

```bash
# Check if a specific version is vulnerable
./script.sh --package-name next --package-version 16.0.3

# Check with version ranges
./script.sh --package-name lodash --package-version '^4.17.0'

# List all occurrences of a package in your project
./script.sh --package-name express
```

This feature creates a virtual PURL internally and scans your project for it.

**Use cases:**

- Pre-installation checks: "Is this version safe before I `npm install`?"
- Quick lookups: "Which versions of this package are being used?"
- Security research: "Where is this vulnerable package in my codebase?"
- Version range testing: "Does `^4.17.0` cover vulnerable versions?"

**Supported version ranges:**

- Exact versions: `1.2.3`
- Greater/less than: `>=1.0.0 <2.0.0`
- Tilde ranges: `~1.2.3` (equivalent to `>=1.2.3 <1.3.0`)
- Caret ranges: `^1.2.3` (equivalent to `>=1.2.3 <2.0.0`)
- Wildcard: `*` (matches any version)

---

## 📚 Documentation & Resources

For more detailed information, see the [`docs/`](docs/) directory:

- **[Docker Usage](docs/docker.md)** — Complete guide to using Docker images
- **[Data Formats](docs/data-formats.md)** — Complete specification of JSON, CSV, PURL formats
- **[Vulnerability Feeds](docs/vulnerability-feeds.md)** — Guide to built-in GHSA/OSV feeds and generating custom feeds
- **[Vulnerability Scanning Tools](docs/vulnerability-scanning-tools.md)** — Guide to Trivy, Grype, Syft, OSV-Scanner, and other tools
- **[Configuration](docs/configuration.md)** — Detailed configuration reference
- **[GitHub Integration](docs/github.md)** — Advanced GitHub scanning features
- **[CI/CD Integration](docs/ci.md)** — Examples for GitHub Actions, GitLab CI, and more
- **[Testing](docs/testing.md)** — Testing guide with fixtures and examples
- **[Contributing](docs/contributing.md)** — Development workflow, commit conventions, and versioning

### Use Cases

- **Security Teams**: Maintain internal vulnerability databases
- **Compliance**: Enforce company-specific security policies
- **CI/CD Pipelines**: Automated vulnerability checks
- **Incident Response**: Quick scans during security incidents
- **Supply Chain Security**: Monitor dependencies across multiple projects

## 📝 Changelog

All releases and changes are documented in the [CHANGELOG.md](CHANGELOG.md).

Releases are automated based on [Conventional Commits](https://conventionalcommits.org):

- **Major** (X.0.0): Breaking changes (`feat!:`, `fix!:`, etc.)
- **Minor** (x.Y.0): New features (`feat:`)
- **Patch** (x.y.Z): Bug fixes and documentation (`fix:`, `docs:`, `perf:`)

## 📄 License

MIT License — see the [`LICENSE`](LICENSE) file for details.

---

**Questions or issues?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).
