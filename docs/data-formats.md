# Data formats

package-checker.sh consumes one or more **vulnerability databases**. You can use:

- **Built-in feeds** (recommended): Pre-generated GHSA and OSV feeds in the `data/` folder
- **Your own custom databases**: JSON, CSV, or PURL files
- **Scanner outputs**: SARIF, SBOM (CycloneDX), or Trivy JSON from tools like Trivy, Grype, OSV-Scanner, etc.

## Built-in Vulnerability Feeds

The repository includes pre-generated vulnerability feeds that are automatically updated every 12 hours:

- `data/ghsa.purl` — GitHub Security Advisory database (~5,000+ npm vulnerabilities)
- `data/osv.purl` — Open Source Vulnerabilities database (~206,000+ npm vulnerabilities)

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
./script.sh --package-name lodash --package-version 4.17.20
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

The feeds are in PURL format with metadata (severity, GHSA ID, CVE, source) as query parameters. See the [vulnerability feeds documentation](./vulnerability-feeds.md) for detailed information.

## Custom Vulnerability Database Formats

Three custom formats are supported for your own vulnerability databases:

- **JSON** — flexible structure with named fields for exact versions and version ranges
- **CSV** — simple table, typically with `name` and `versions` columns
- **PURL** — Package URL format, a standardized way to identify software packages

## JSON format

JSON sources are objects where keys are package names. Each package entry can contain:

- `versions`: list of **exact vulnerable versions**
- `versions_range`: list of **version range expressions**

Example:

```json
{
  "package-name": {
    "versions": ["1.0.0", "2.0.0"]
  },
  "lodash": {
    "versions_range": [">=4.0.0 <4.17.21"]
  }
}
```

You can mix `versions` and `versions_range` entries for the same package if needed.

## CSV format

CSV sources are usually two-column files with a header:

```csv
name,versions
express,4.16.0
lodash,">=4.0.0 <4.17.21"
```

- `name` — package to match in `dependencies` / lockfiles.
- `versions` — either a single version (e.g. `4.16.0`) or a range (e.g. `">=4.0.0 <4.17.21"`).

If your CSV uses a different layout, specify the columns explicitly:

```bash
./script.sh --source ./vulns.csv --format csv --csv-columns "name,versions"
```

## PURL format

PURL (Package URL) is a standardized format for identifying software packages. Each line contains a package URL in the format:

```text
pkg:type/namespace/name@version
```

Examples:

```text
pkg:npm/lodash@4.17.21
pkg:npm/express@4.16.0
pkg:npm/@babel/core@7.12.0
pkg:npm/react@>=16.0.0 <16.14.0
```

- `type` — package ecosystem (e.g., `npm`, `pypi`, `maven`)
- `namespace` — optional namespace or scope (e.g., `@babel`)
- `name` — package name
- `version` — exact version or version range

**Key features:**

- One package per line
- Supports exact versions: `pkg:npm/lodash@4.17.21`
- Supports version ranges: `pkg:npm/express@>=4.0.0 <4.17.0`
- Empty lines and lines starting with `#` are ignored (comments)
- The package name is extracted from the last component of the path

Example PURL file:

```purl
# Critical vulnerabilities
pkg:npm/lodash@4.17.20
pkg:npm/minimist@0.0.8

# Version ranges
pkg:npm/express@>=4.0.0 <4.17.21
pkg:npm/@babel/traverse@<7.23.2
```

To use a PURL file:

```bash
./script.sh --source ./vulns.purl --format purl
```

## Version ranges

Version ranges follow standard npm semver style. Supported formats:

- **Exact versions**: `1.2.3`
- **Comparison operators**: `>=4.0.0 <4.17.21`, `>1.0.0`, `<=2.0.0`
- **Tilde ranges**: `~1.2.3` (equivalent to `>=1.2.3 <1.3.0`)
- **Caret ranges**: `^1.2.3` (equivalent to `>=1.2.3 <2.0.0`)

When a range contains spaces, make sure it is quoted in CSV files so the shell and CSV parser treat it as a single field.

## Direct Package Lookup

You can query the vulnerability database for a specific package without scanning your project:

```bash
# Check against built-in GHSA feed
./script.sh --source data/ghsa.purl --package-name express --package-version 4.17.1

# List all vulnerable versions of a package
./script.sh --source data/ghsa.purl --package-name lodash

# Check with version ranges
./script.sh --source data/ghsa.purl --package-name react --package-version '^17.0.0'

# Use custom vulnerability database
./script.sh --source vulns.json --package-name next --package-version 16.0.3
```

This is useful for:

- Quick vulnerability checks before installing a package
- Verifying if a specific version is safe
- Security research and dependency investigation

## Configuration File

Create a `.package-checker.config.json` in your project root for persistent configuration:

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

Use it with:

```bash
./script.sh --config .package-checker.config.json
```

## Adding Metadata to Vulnerability Databases

You can enrich vulnerability databases with metadata like severity, CVE IDs, and GHSA identifiers.

### JSON Format with Metadata

```json
{
  "express": {
    "versions": ["4.16.0"],
    "severity": "high",
    "cve": "CVE-2022-24999",
    "ghsa": "GHSA-rv95-896h-c2vc"
  },
  "lodash": {
    "versions_range": [">=4.17.0 <4.17.21"],
    "severity": "critical",
    "cve": "CVE-2020-8203",
    "ghsa": "GHSA-p6mc-m468-83gw"
  }
}
```

### PURL Format with Metadata

PURL supports metadata via query parameters:

```text
pkg:npm/express@4.16.0?severity=high&ghsa=GHSA-rv95-896h-c2vc&cve=CVE-2022-24999&source=ghsa
pkg:npm/lodash@4.17.20?severity=critical&ghsa=GHSA-p6mc-m468-83gw&cve=CVE-2020-8203&source=osv
```

### CSV Format with Metadata

Add additional columns for metadata:

```csv
name,versions,severity,ghsa,cve,source
express,4.16.0,high,GHSA-rv95-896h-c2vc,CVE-2022-24999,ghsa
lodash,4.17.20,critical,GHSA-p6mc-m468-83gw,CVE-2020-8203,osv
```

Specify the columns when using:

```bash
./script.sh --source vulns.csv --format csv --csv-columns "name,versions"
```

### Exporting Results with Metadata

When you export scan results, metadata is automatically included:

```bash
# Export to JSON
./script.sh --source data/ghsa.purl --export-json results.json

# Export to CSV
./script.sh --source data/ghsa.purl --export-csv results.csv
```

**JSON export example:**

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

**CSV export example:**

```csv
package,file,severity,ghsa,cve,source
express@4.16.0,./package-lock.json,medium,GHSA-rv95-896h-c2vc,CVE-2022-24999,ghsa
lodash@4.17.20,./package-lock.json,high,GHSA-p6mc-m468-83gw,CVE-2020-8203,ghsa
```

## Scanner Output Formats

package-checker.sh can consume vulnerability reports from external scanners like Trivy, Semgrep, OSV-Scanner, Grype, and Syft.

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

**Notes:**

- Auto-detected for `.trivy.json` and `.trivy` file extensions
- Extracts package names and installed versions from Trivy's `Results` array
- Works with both filesystem and container image scans
- Compatible with all Trivy vulnerability databases

### Alternative Tools

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

For more detailed information on using these tools, see the [Vulnerability Scanning Tools](./vulnerability-scanning-tools.md) guide.
