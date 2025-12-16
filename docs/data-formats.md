# Data formats

package-checker.sh consumes one or more **vulnerability databases**. You can use:

- **Built-in feeds** (recommended): Pre-generated GHSA and OSV feeds in the `data/` folder
- **Your own custom databases**: JSON, CSV, or PURL files
- **Scanner outputs**: SARIF, SBOM (CycloneDX), or Trivy JSON from tools like Trivy, Grype, OSV-Scanner, etc.

## Built-in Vulnerability Feeds

The repository includes pre-generated vulnerability feeds that are automatically updated every 12 hours:

- `data/ghsa.purl` — GitHub Security Advisory database (~5,000+ npm vulnerabilities)
- `data/osv.purl` — Open Source Vulnerabilities database (~206,000+ npm vulnerabilities)

**Quick start:**

```bash
# Use GHSA feed
./script.sh --source data/ghsa.purl

# Use both GHSA and OSV for comprehensive coverage
./script.sh --source data/ghsa.purl --source data/osv.purl
```

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

## Scanner Output Formats

package-checker.sh can consume vulnerability reports from external scanners. See the [Vulnerability Scanning Tools](./vulnerability-scanning-tools.md) guide for detailed information on:

- **SARIF** format (from Trivy, Semgrep, OSV-Scanner, etc.)
- **SBOM CycloneDX** format (from Trivy, Syft, Grype, etc.)
- **Trivy JSON** format (from Trivy native output)
