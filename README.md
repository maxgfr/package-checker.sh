# package-checker.sh

A flexible, lightweight shell script to detect vulnerable npm packages against custom vulnerability databases. Check your Node.js projects for known vulnerable package versions using your own data sources.

## 📦 Overview

**package-checker.sh** scans your JavaScript/TypeScript projects for vulnerable dependencies using custom vulnerability databases. Works with npm, Yarn, pnpm, Bun, and Deno projects.

### Key Features

- **Custom Data Sources**: Use your own JSON, CSV, or PURL vulnerability lists (local or remote)
- **Version Ranges**: Define ranges like `>=1.0.0 <2.0.0` instead of listing every version
- **Multiple Package Managers**: Full support for npm, Yarn (Classic & Berry/v2+), pnpm, Bun, and Deno
- **GitHub Integration**: Scan entire organizations or individual repositories directly from GitHub
- **Zero Dependencies**: Only requires `curl` (pre-installed on most systems)
- **Flexible Configuration**: Use CLI arguments or `.package-checker.config.json` file

### Prerequisites

- **curl** (required) — usually pre-installed on macOS and Linux
- No Node.js, jq, or other dependencies needed

---

## 🚀 Getting Started

### Installation

Download the script:

```bash
curl -O https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh
chmod +x script.sh
```

Or clone the repository:

```bash
git clone https://github.com/maxgfr/package-checker.sh.git
cd package-checker.sh
```

### Quick Start

Test with included fixtures:

```bash
cd test-fixtures
../script.sh --source ./test-vulnerabilities.json
```

### Basic Usage

```bash
# Scan with a JSON vulnerability file
./script.sh --source https://your-domain.com/vulnerabilities.json

# Scan with a CSV file
./script.sh --source https://your-domain.com/vulnerabilities.csv

# Scan with a PURL file
./script.sh --source https://your-domain.com/vulnerabilities.purl

# Scan with SARIF format (from Trivy, Semgrep, etc.)
./script.sh --source vulnerabilities.sarif --format sarif

# Scan with SBOM CycloneDX format
./script.sh --source sbom.cdx.json --format sbom-cyclonedx

# Scan with Trivy JSON format
./script.sh --source trivy-report.json --format trivy-json

# Multiple sources (mixed formats)
./script.sh --source source1.json --source source2.purl --format purl

# Use configuration file
./script.sh --config .package-checker.config.json

# Direct execution (one-liner)
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh | bash -s -- --source https://your-domain.com/vulns.json
```

### Command-Line Options

```text
-h, --help                Show help message
-s, --source SOURCE       Vulnerability source (repeatable for multiple sources)
-f, --format FORMAT       Data format: json, csv, purl, sarif, sbom-cyclonedx, or trivy-json (auto-detected from extension)
--csv-columns COLS        CSV columns: "package_name,package_versions" or "1,2"
-c, --config FILE         Path to configuration file
--no-config               Skip loading configuration file
--github-org ORG          GitHub organization to scan
--github-repo owner/repo  Single GitHub repository to scan
--github-token TOKEN      GitHub token (or use GITHUB_TOKEN env var)
--github-output DIR       Output directory for fetched files (default: ./packages)
--github-only             Only fetch from GitHub, skip local analysis
```

---

## ⚙️ Configuration & Data Formats

### Configuration File

Create a `.package-checker.config.json` in your project root:

```json
{
  "sources": [
    {
      "url": "https://example.com/vulnerabilities.json",
      "name": "Company Security Database"
    },
    {
      "url": "https://example.com/vulnerabilities.csv",
      "format": "csv",
      "columns": "package_name,package_versions",
      "name": "Custom Vulnerabilities"
    },
    {
      "url": "https://example.com/vulnerabilities.purl",
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
    "package_versions": ["4.16.0", "4.16.1"]
  },
  "lodash": {
    "package_versions_range": [">=4.17.0 <4.17.21"]
  },
  "axios": {
    "package_versions": ["0.21.0"],
    "package_versions_range": [">=0.18.0 <0.21.2"]
  }
}
```

**Fields:**
- `package_versions`: Array of exact vulnerable versions
- `package_versions_range`: Array of version ranges with operators (`>=`, `>`, `<`, `<=`)

### CSV Format

Example vulnerability database ([`example-vulnerabilities.csv`](example-vulnerabilities.csv)):

```csv
package_name,package_versions
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

---

## 📚 Documentation & Resources

For more detailed information, see the [`docs/`](docs/) directory:

- **[Data Formats](docs/data-formats.md)** — Complete specification of JSON and CSV formats
- **[Vulnerability Scanning Tools](docs/vulnerability-scanning-tools.md)** — Guide to Trivy, Grype, Syft, OSV-Scanner, and other tools for generating SARIF, SBOM, and Trivy JSON reports
- **[Configuration](docs/configuration.md)** — Detailed configuration reference
- **[GitHub Integration](docs/github.md)** — Advanced GitHub scanning features
- **[CI/CD Integration](docs/ci.md)** — Examples for GitHub Actions, GitLab CI, and more
- **[Testing](docs/testing.md)** — Testing guide with fixtures and examples

### Use Cases

- **Security Teams**: Maintain internal vulnerability databases
- **Compliance**: Enforce company-specific security policies
- **CI/CD Pipelines**: Automated vulnerability checks
- **Incident Response**: Quick scans during security incidents
- **Supply Chain Security**: Monitor dependencies across multiple projects

### Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

### License

MIT License — see the [`LICENSE`](LICENSE) file for details.

---

**Questions or issues?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).
