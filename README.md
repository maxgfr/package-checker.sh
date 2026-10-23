# package-checker.sh

Detect vulnerable packages across **12 ecosystems** with a flexible, lightweight shell script. Includes built-in GHSA and OSV vulnerability feeds with 200,000+ npm vulnerabilities (plus per-ecosystem feeds for the rest), or use your own custom databases.

## 📦 Overview

**package-checker.sh** scans your projects for vulnerable dependencies across npm/JavaScript, Python, Go, Rust, Ruby, PHP, Java/JVM (Maven & Gradle), .NET (NuGet), Dart/Flutter, Elixir, Swift, and GitHub Actions workflows. It auto-detects the lockfiles/manifests present and only loads the feeds those ecosystems need.

> **npm users:** nothing changes for you. npm remains the default ecosystem, the npm console output is byte-for-byte identical to previous releases, and the default Docker/Homebrew installs still ship the npm feeds. The other ecosystems are additive.

### Key Features

- **12 Ecosystems**: npm, PyPI, Go, Cargo (Rust), RubyGems, Composer (PHP), Maven/Gradle, NuGet, Pub (Dart), Hex (Elixir), Swift, and GitHub Actions — see the [ecosystems table](#-supported-ecosystems)
- **Runtime CVEs (Node.js / PHP)**: the runtime versions your project targets (`.nvmrc`, `.tool-versions`, `engines`, `FROM node:`/`FROM php:`, `config.platform.php`, workflow `node-version:`…) are checked against the OSV Bitnami advisories — see [Runtime versions](#runtime-versions-nodejs--php)
- **Built-in Vulnerability Feeds**: GHSA and OSV feeds with 200,000+ npm vulnerabilities included, plus per-ecosystem feeds for every other language (auto-updated every 12 hours)
- **Detect-then-load**: scanning detects the ecosystems in your repo and downloads only the feeds they need — never a single combined all-ecosystems file
- **Docker Images Available**: Full image (~43MB, npm feeds) or lightweight (~27MB), plus an all-ecosystems variant
- **Custom Data Sources**: Add your own JSON, CSV, or PURL vulnerability lists
- **Scanner Integration**: Consume SARIF, SBOM, or Trivy JSON from external tools
- **Version Ranges**: Define ranges like `>=1.0.0 <2.0.0` instead of listing every version
- **Multiple Package Managers**: Full support for npm, Yarn (Classic & Berry/v2+), pnpm, Bun, and Deno — plus one or more lockfiles for each of the other 11 ecosystems
- **GitHub Integration**: Scan entire organizations or individual repositories directly from GitHub
- **Zero Dependencies**: Only requires `bash`, `awk`, and `curl`
- **Flexible Configuration**: Use CLI arguments or `.package-checker.config.json` file

### 🌐 Supported Ecosystems

Each ecosystem is discovered by its lockfiles/manifests and scanned against its own GHSA/OSV feed. npm keeps the historical feed filenames (`ghsa.purl` / `osv.purl`); every other ecosystem uses `ghsa-<eco>.purl` / `osv-<eco>.purl`.

| Ecosystem (purl type) | Lockfiles / manifests scanned | Built-in feed files | `--lockfile-types` alias(es) |
|---|---|---|---|
| `npm` | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `deno.lock`, `package.json` | `ghsa.purl`, `osv.purl` | `npm`, `yarn`, `pnpm`, `bun`, `deno` |
| `pypi` | `requirements.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock` | `ghsa-pypi.purl`, `osv-pypi.purl` | `python` |
| `golang` | `go.sum`, `go.mod` | `ghsa-golang.purl`, `osv-golang.purl` | `go` |
| `cargo` | `Cargo.lock` | `ghsa-cargo.purl`, `osv-cargo.purl` | `rust` |
| `gem` | `Gemfile.lock` | `ghsa-gem.purl`, `osv-gem.purl` | `ruby` |
| `composer` | `composer.lock` | `ghsa-composer.purl`, `osv-composer.purl` | `php` |
| `maven` | `gradle.lockfile`, `pom.xml` | `ghsa-maven.purl`, `osv-maven.purl` | `maven` |
| `nuget` | `packages.lock.json` | `ghsa-nuget.purl`, `osv-nuget.purl` | `nuget` |
| `pub` | `pubspec.lock` | `ghsa-pub.purl`, `osv-pub.purl` | `dart` |
| `hex` | `mix.lock` | `ghsa-hex.purl`, `osv-hex.purl` | `hex` |
| `swift` | `Package.resolved` | `ghsa-swift.purl`, `osv-swift.purl` | `swift` |
| `githubactions` | `.github/workflows/*.yml`, `*.yaml` | `ghsa-githubactions.purl`, `osv-githubactions.purl` | `actions` |

When you run a scan, package-checker detects which of these are present and loads only the matching feeds (the **separation guarantee**: per-ecosystem feed files only, never a single combined file). Override detection with `--ecosystems` or restrict discovery with `--lockfile-types`.

### Prerequisites

- **bash 4+** — Shell interpreter (macOS users need Homebrew Bash; the system Bash 3.2 is too old)
- **awk** (gawk or mawk) — Usually pre-installed
- **curl** — For remote sources and GitHub API
- Or use Docker images (no installation required)

---

## 💪 Design & Footprint — why it stays small

The whole tool is **one self-contained `script.sh`** with **zero runtime dependencies** on the scan path (only `bash`, `awk`, `curl` — no Node, no Python, no package manager, no install step). `jq` is only needed to *regenerate* feeds or open GitHub issues, never to scan.

The important design choice for scale is that **vulnerability data is split into one small file per ecosystem — never a single combined bundle.** Scanning **detects the ecosystems in your repo and loads only their feeds** (detect-then-load). A Rust-only project pulls ~0.5 MB; it never touches the 16 MB npm database. This keeps memory bounded and downloads minimal no matter how many ecosystems the tool supports.

Within a feed, entries are **pre-filtered on the package names your project contains**: one pass collects the name tokens of every lockfile and manifest, and only feed entries whose name can match are kept (a superset, so nothing relevant is dropped). A 19k-line pnpm lockfile scanned against GHSA + OSV keeps about 1,000 of 255,000 entries and finishes in about a second. Set `PACKAGE_CHECKER_NO_PREFILTER=1` to turn the filter off when diagnosing a result.

### What a scan actually loads

| You scan… | Feeds loaded | Size pulled |
|---|---|---|
| a Rust repo (`Cargo.lock`) | `ghsa-cargo` + `osv-cargo` | **~0.5 MB** |
| a Python repo (`requirements.txt`) | `ghsa-pypi` + `osv-pypi` | **~4 MB** |
| a Go repo (`go.sum`) | `ghsa-golang` + `osv-golang` | **~3 MB** |
| an npm repo, GHSA only (default) | `ghsa.purl` | **~1 MB** |
| a polyglot repo (npm + Python + Go) | only those 3 ecosystems' feeds | just their sum |
| any repo that pins a Node.js or PHP version | + `osv-runtime.purl` | **~75 KB** |
| **everything at once** | all 24 files | ~32 MB total (npm OSV alone is 16 MB) |

Per-ecosystem feed sizes (GHSA / OSV), so you can see nothing is oversized:

| npm | pypi | golang | maven | composer | cargo | nuget | gem | hex | pub | swift | actions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1.0M / 15.5M | 1.1M / 2.9M | 1.0M / 1.8M | 1.6M / 1.3M | 1.4M / 1.1M | 0.2M / 0.3M | 0.8M / 0.9M | 0.2M / 0.5M | 15K / 44K | 1K / 1K | 9K / 7K | 7K / 6K |

The npm OSV feed (mostly malware advisories) is the only large file, and it loads only for npm scans that explicitly opt into OSV.

### Docker keeps images small the same way

Feeds are baked at build time via the `FEED_ECOSYSTEMS` build-arg, so you pick the image size:

| Variant | Image | Baked feeds |
|---|---|---|
| `…-lite` | `ghcr.io/maxgfr/package-checker.sh-lite` | none — bring your own (~27 MB) |
| default | `ghcr.io/maxgfr/package-checker.sh` | **npm only** (~43 MB, unchanged from before) |
| `…-all` | `ghcr.io/maxgfr/package-checker.sh-all` | all 12 ecosystems |

Anything not baked in is fetched on demand at runtime from the per-ecosystem files on GitHub — so even the small default image scans any language.

---

## 🚀 Getting Started

### Option 1: Homebrew Installation (Recommended for macOS/Linux)

The easiest way to install and use `package-checker`:

```bash
# Install package-checker
brew install maxgfr/tap/package-checker

# Use it directly (uses default GHSA feed automatically)
package-checker

# Or explicitly specify GHSA feed
package-checker --default-source-ghsa

# Or with both GHSA and OSV feeds
package-checker --default-source-ghsa-osv

# Check specific package version
package-checker --package-name express --package-version 4.17.1

# Scan with custom vulnerability file
package-checker --source custom-vulns.json
```

### Option 2: One-Click Install & Run (Quickest)

Run directly from the web with your own vulnerability data:

```bash
# Run with remote vulnerability source
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh | bash -s -- --source https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl

# Or with local source file
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh | bash -s -- --source ./vulns.json
```

### Option 3: Using Docker

The easiest way to get started with built-in vulnerability feeds. Three variants are published (feeds are selected at build time via the `FEED_ECOSYSTEMS` build-arg):

| Variant | Image | Built-in feeds |
|---|---|---|
| Lite | `ghcr.io/maxgfr/package-checker.sh-lite:latest` | none (bring your own) |
| Full (default) | `ghcr.io/maxgfr/package-checker.sh:latest` | npm only (`ghsa.purl` + `osv.purl`) — identical size/content to before |
| Full — all ecosystems | `ghcr.io/maxgfr/package-checker.sh-all:latest` | all 12 ecosystems (`ghsa-*` / `osv-*`) |

The default full image bakes in **only** the npm feeds to stay small; any ecosystem not baked in is auto-fetched at runtime from raw GitHub (detect-then-load). See the [Docker documentation](docs/docker.md) for the `FEED_ECOSYSTEMS` build-arg and offline usage.

```bash
# Scan current directory (uses default GHSA feed automatically)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest

# Or explicitly use GHSA feed
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa

# Or use both GHSA and OSV feeds for comprehensive coverage
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa-osv

# Scan a specific subdirectory
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest /workspace/my-project --default-source-ghsa-osv

# Use with your own data files
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --source my-vulns.json
```

### Basic Usage Examples

```bash
# Scan current directory (uses default GHSA source automatically)
package-checker

# Scan specific directory (relative or absolute path)
package-checker ./my-project
package-checker /absolute/path/to/project

# Scan a Python project (auto-detects requirements.txt/poetry.lock/… and
# loads the pypi feeds only)
package-checker ./my-python-app --default-source-ghsa-osv

# Scan a polyglot repo (npm + Python + Go in one pass) — each finding is
# labelled with its ecosystem, and JSON/CSV exports carry an `ecosystem` field
package-checker ./polyglot-repo --default-source-ghsa-osv --export-json report.json

# Restrict which ecosystems' feeds are loaded (overrides auto-detection)
package-checker --ecosystems npm,pypi

# Use both GHSA and OSV sources for comprehensive coverage
package-checker --default-source-ghsa-osv

# Use only OSV source instead of default GHSA
package-checker --default-source-osv

# Check specific package version
package-checker --package-name express --package-version 4.17.1

# Check with version ranges
package-checker --package-name lodash --package-version '^4.17.0'

# Scan with custom vulnerability file
package-checker --source custom-vulns.json

# Scan specific folder with custom source
package-checker ./subfolder --source custom-vulns.json

# Multiple sources (built-in + custom)
package-checker --default-source-ghsa-osv --source custom-vulns.csv

# Use configuration file
package-checker --config .package-checker.config.json

# Scan GitHub organization
package-checker --default-source-ghsa-osv --github-org myorg --github-token $GITHUB_TOKEN
```

---

## 👀 Command-Line Options

```text
ARGUMENTS:
PATH                        Directory to scan (default: current directory)
                            Can be relative (./my-project) or absolute (/path/to/project)

OPTIONS:
-h, --help                  Show help message
--help-ai                   Show AI help menu
--help-ai prompt            Output the AI system prompt (prompt.md)
--help-ai doc               Output the full AI guide (docs/ai-guide.md)
-s, --source SOURCE         Vulnerability source (repeatable for multiple sources)
--default-source-ghsa       Use default GHSA source (default if no source specified)
--default-source-osv        Use default OSV source
--default-source-ghsa-osv            Use both default GHSA and OSV sources (recommended for comprehensive coverage)
-f, --format FORMAT         Format of the preceding -s source: json, csv, purl, sarif,
                            sbom-cyclonedx or trivy-json (auto-detected from extension)
--csv-columns COLS          CSV columns of the preceding -s source: "name,versions" or "1,2"
--package-name NAME         Check vulnerability for a specific package name
--package-version VER       Check specific version (requires --package-name)
--ecosystem ECO             Ecosystem for --package-name (default: npm). One of:
                            npm, pypi, golang, maven, cargo, gem, composer,
                            nuget, pub, hex, swift, githubactions, runtime
                            (Node.js / PHP: --package-name node --ecosystem runtime)
-c, --config FILE           Path to configuration file (always read when given)
--no-config                 Skip the default .package-checker.config.json
--export-json [FILE]      Export results to JSON (FILE optional, default: vulnerabilities.json)
--export-csv [FILE]       Export results to CSV (FILE optional, default: vulnerabilities.csv)
--github-org ORG          GitHub organization to scan
--github-repo owner/repo  Single GitHub repository to scan
--github-token TOKEN      GitHub token (or use GITHUB_TOKEN env var)
--github-output DIR       Output directory for fetched files (default: ./packages)
--github-only             Only fetch from GitHub, skip local analysis
--create-multiple-issues  Create one GitHub issue per vulnerable package (requires --github-token)
--create-single-issue     Create a single consolidated issue with all vulnerabilities (requires --github-token)
--fetch-all DIR           Fetch GHSA + OSV feeds for ALL ecosystems to DIR (default: data)
--fetch-osv [ECOS]        Fetch OSV feeds; optional comma list of ecosystems (default: all)
--fetch-ghsa [ECOS]       Fetch GHSA feeds; optional comma list of ecosystems (default: all)
--fetch-runtime [DIR]     Fetch the Node.js / PHP runtime feed (OSV Bitnami) to
                          DIR/osv-runtime.purl (default: data)
--only-package-json       Scan only package.json files (skip lockfiles)
--only-lockfiles          Scan only lockfiles (skip package.json files)
--lockfile-types TYPES    Comma-separated lockfile types to scan. npm family:
                          npm, yarn, pnpm, bun, deno. Other ecosystems: python,
                          go, rust, ruby, php, maven, nuget, dart, hex, swift,
                          actions (GitHub Actions workflows)
--ecosystems ECOS         Comma-separated ecosystems to load default feeds for,
                          overriding auto-detection (aliases above or purl types
                          like npm, pypi, golang, cargo, githubactions)
--sbom FILE               Also scan the components of a CycloneDX JSON SBOM, like
                          a lockfile (repeatable). Use it for Maven transitive
                          dependencies, which pom.xml does not list
--go-reachability         Annotate each Go finding "called" or "not called" with
                          govulncheck, when it is installed (exit code unchanged)
--no-runtime-check        Do not check the Node.js / PHP versions the project targets
--include-gitignored      Also scan git-ignored lockfiles and manifests (skipped
                          and listed by default)

EXIT CODES:
0   No vulnerable package found
1   Vulnerable packages found
2   Error: invalid usage, unreadable or empty data source, failed scan
```

Any non-zero exit code fails a CI job. Use `1` vs `2` to tell findings from errors (for example, to report findings without failing while still failing on errors).

---

## ⚙️ Data Formats & Configuration

package-checker.sh supports multiple vulnerability data formats:

### Supported Formats

**Built-in feeds (recommended):**

- `data/ghsa.purl` - GitHub Security Advisories, npm (~10,000 entries, one per affected range)
- `data/osv.purl` - Open Source Vulnerabilities, npm (~245,000 entries, mostly malicious-package advisories)
- `data/ghsa-<eco>.purl` / `data/osv-<eco>.purl` - per-ecosystem feeds for every other language (e.g. `ghsa-pypi.purl`, `osv-golang.purl`). npm keeps the legacy unsuffixed filenames for backward compatibility.
- `data/osv-runtime.purl` - Node.js and PHP runtime advisories (OSV Bitnami ecosystem, `pkg:runtime/node@…` / `pkg:runtime/php@…`), loaded whenever the project pins a runtime version

**Custom formats:**

- **JSON** - Simple key-value format with version ranges
- **CSV** - Tabular format (name, versions)
- **PURL** - Package URL standard format
- **SARIF** - Static analysis results (Trivy, Semgrep, CodeQL)
- **SBOM CycloneDX** - Software Bill of Materials
- **Trivy JSON** - Native Trivy output format

### Quick Examples

**JSON format:**

```json
{
  "express": {
    "versions": ["4.16.0", "4.16.1"],
    "versions_range": [">=4.0.0 <4.17.21"]
  }
}
```

**CSV format:**

```csv
name,versions
express,4.16.0
lodash,">=4.17.0 <4.17.21"
```

**PURL format:**

```text
pkg:npm/lodash@4.17.20
pkg:npm/express@>=4.0.0 <4.17.21
pkg:npm/@babel/traverse@7.23.0
```

**Configuration file (`.package-checker.config.json`):**

```json
{
  "sources": [
    {
      "source": "https://example.com/vulnerabilities.json",
      "name": "Company Security Database"
    }
  ],
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git", "dist"]
  }
}
```

For complete format specifications, see the [Data Formats documentation](docs/data-formats.md).

### What Gets Scanned

**npm lockfiles** (exact version matching):
- `package-lock.json`, `npm-shrinkwrap.json` (npm)
- `yarn.lock` (Yarn Classic & Yarn Berry/v2+)
- `pnpm-lock.yaml` (pnpm)
- `bun.lock` (Bun)
- `deno.lock` (Deno)
- packages installed from a tarball URL are checked too: at the version the lockfile records (npm, yarn, pnpm) or, for bun, the one in the archive name (`xlsx-0.19.3.tgz`)

**package.json** (dependency checking):
- `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`
- skipped when a lockfile covers it (an npm, yarn, pnpm, bun or deno lockfile in the same directory, or in a workspace root above it): the lockfile pins what is installed, while the manifest only declares ranges
- otherwise checked as **declared versions** (the lowest version each range allows); `git+`, `github:`, `catalog:`, `file:`, `patch:` specs and dist-tags such as `latest` are skipped

**Other ecosystems' lockfiles/manifests** (see the [ecosystems table](#-supported-ecosystems) for the full list):
- Python (`requirements.txt`, `requirements-*.txt`, `requirements/*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`), Go (`go.sum`, `go.mod`), Rust (`Cargo.lock`), Ruby (`Gemfile.lock`), PHP (`composer.lock`), Maven/Gradle (`pom.xml`, `gradle.lockfile`), NuGet (`packages.lock.json`), Dart (`pubspec.lock`), Elixir (`mix.lock`), Swift (`Package.resolved`), and GitHub Actions workflows (`.github/workflows/*.yml`)

**CycloneDX SBOMs** (`--sbom FILE`, repeatable): every component with a purl is checked like a lockfile entry, and its ecosystems pick the default feeds. `metadata.component` (the project itself) is not.

**Maven: transitive dependencies.** `pom.xml` lists only the direct dependencies, and only those with a version in the file: versions managed by a parent POM or a BOM are not there, and neither are the transitive dependencies. The scan says how many dependencies it could not check. To check them all, generate a CycloneDX SBOM and scan it:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
package-checker --sbom target/bom.json --default-source-ghsa-osv
```

With Gradle, enable [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html): the `gradle.lockfile` it writes lists every resolved version.

**Go: reachability.** `--go-reachability` runs [govulncheck](https://go.dev/doc/tutorial/govulncheck) in each Go module that has a finding and annotates the finding `called` (the code reaches a vulnerable function) or `not called`. The annotation appears in the summary and in the exports (`reachability`). A `not called` finding is still reported, and the exit code does not change. Without govulncheck (`go install golang.org/x/vuln/cmd/govulncheck@latest`), the scan warns and runs as usual.

### Runtime versions (Node.js / PHP)

Dependencies are not the only attack surface: the runtime itself ships CVEs (Node2Shell, CVE-2026-111497, fixed in Node.js 22.23.4 / 24.22.1 / 26.12.1; PHP2Shell, CVE-2026-109618/109619, fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). Every scan also reads the runtime versions the project targets:

| Runtime | Read from |
|---|---|
| Node.js | `.nvmrc`, `.node-version`, `.tool-versions` (`nodejs`), `package.json` `engines.node` and `volta.node`, `Dockerfile*` `FROM node:TAG`, `.github/workflows/*.yml` `node-version:` |
| PHP | `composer.json` `config.platform.php` and `require.php`, `composer.lock` `platform-overrides.php`, `.php-version`, `.tool-versions` (`php`), `Dockerfile*` `FROM php:TAG`, workflow `php-version:` |

They are checked against `data/osv-runtime.purl` (OSV Bitnami advisories, refreshed every 12 hours with the other feeds):

- **an exact version** (`22.1.0`, `FROM php:8.3.10-fpm`) is a regular finding, reported as `[runtime] node@22.1.0` with its CVEs and fix, included in the exports, exit code 1;
- **a release line** (`20`, `8.3`, `node:20-alpine`) floats to its latest release: it only warns when no release of the line is fixed (an end-of-life line), e.g. `Node.js 20: no release of this line fixes CVE-2026-111497; move to >= 22.23.4`;
- **a range** (`>=18`, `^8.1`) warns when its lowest allowed version is vulnerable: `Node.js >=18 allows vulnerable versions (…); raise the minimum to >= 22.23.4`.

Warnings are listed again in the summary and never change the exit code. Values that name no version (`lts/*`, `latest`, `${NODE_VERSION}`) are ignored. Turn the check off with `--no-runtime-check` or `"options": {"runtime_check": false}`.

### Filtering File Types

By default, package-checker scans **both** lockfiles and package.json files. You can control what gets scanned:

**Scan only package.json files:**
```bash
# Skip all lockfiles, only scan package.json
package-checker --source vulns.json --only-package-json
```

**Scan only lockfiles:**
```bash
# Skip package.json files, only scan lockfiles
package-checker --source vulns.json --only-lockfiles
```

**Scan specific lockfile types:**
```bash
# Only scan yarn.lock files
package-checker --source vulns.json --lockfile-types yarn

# Only scan npm and yarn lockfiles (skip pnpm, bun, deno)
package-checker --source vulns.json --lockfile-types npm,yarn

# Scan only the Python and Go lockfiles in a polyglot repo
package-checker --source vulns.json --lockfile-types python,go

# Combine with --only-lockfiles
package-checker --source vulns.json --only-lockfiles --lockfile-types yarn
```

Available lockfile types: `npm`, `yarn`, `pnpm`, `bun`, `deno` (npm family) and `python`, `go`, `rust`, `ruby`, `php`, `maven`, `nuget`, `dart`, `hex`, `swift`, `actions` (other ecosystems).

### Exporting Results

You can export scan results to JSON or CSV format for further analysis, reporting, or integration with other tools.

**Export to JSON:**
```bash
# Export with custom filename
package-checker --source vulns.json --export-json results.json
```

**Export to CSV:**
```bash
# Export with custom filename
package-checker --source vulns.json --export-csv results.csv
```

**Export both formats:**
```bash
package-checker --source vulns.json --export-json output.json --export-csv output.csv
```

**JSON Export Format:**

The JSON export includes detailed vulnerability information with metadata:

```json
{
  "vulnerabilities": [
    {
      "package": "express@4.16.0",
      "name": "express",
      "version": "4.16.0",
      "file": "./package-lock.json",
      "ecosystem": "npm",
      "severity": "moderate",
      "ghsa": "GHSA-rv95-896h-c2vc",
      "cve": "CVE-2022-24999",
      "source": "ghsa, osv",
      "fixed_in": "4.17.3",
      "advisories": [
        {"severity": "moderate", "ghsa": "GHSA-rv95-896h-c2vc", "cve": "CVE-2022-24999", "id": "", "source": "ghsa, osv", "fix": "4.17.3"}
      ]
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
package,file,severity,ghsa,cve,source,ecosystem,version,fix,reachability
"express@4.16.0","./package-lock.json","moderate","GHSA-rv95-896h-c2vc","CVE-2022-24999","ghsa, osv","npm","4.16.0","4.17.3",""
"lodash@4.17.20","./package-lock.json","high","GHSA-p6mc-m468-83gw","CVE-2020-8203","ghsa","npm","4.17.20","4.17.21",""
```

**Notes:**

- Reports are always written, even when nothing is vulnerable (an empty list), so a CI job never reads a stale report
- `reachability` (`called` or `not called`) is set only for Go findings scanned with `--go-reachability`; the CSV column stays empty otherwise
- The same advisory published by GHSA and OSV is merged into one entry (`"source": "ghsa, osv"`); top-level fields describe the most severe advisory and `fixed_in` is the version that fixes all of them
- CSV cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets do not run them as formulas (scoped npm names read `'@scope/name@1.0.0`)
- Metadata fields (severity, GHSA, CVE, source) are included when available in the vulnerability database
- See the [Data Formats documentation](docs/data-formats.md) for details on adding metadata to your vulnerability sources

---

## 🔄 CI/CD Integration

Use the reusable GitHub Actions workflow for zero-config vulnerability scanning:

```yaml
name: Security Check

on:
  push:
    branches: [ main ]
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  vulnerability-check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-osv: true  # Add OSV in addition to default GHSA
      fail-on-vulnerabilities: true
```

**Benefits:**

- No installation or configuration required
- Uses built-in GHSA feed by default (auto-updated every 12 hours with 200,000+ vulnerabilities)
- Optionally add OSV feed for even more comprehensive coverage
- Works with npm, Yarn, pnpm, Bun, and Deno projects
- Automatic security reports in PR checks

For more examples and other CI systems (GitLab CI, etc.), see the [CI/CD Integration documentation](docs/ci.md).

---

## 🧑‍💻 GitHub Integration

**Scan an entire organization:**
```bash
package-checker --github-org myorg --github-token ghp_xxx --source vulns.json
```

**Scan a single repository:**
```bash
# Public repo (no token needed)
package-checker --github-repo owner/repo --source vulns.json

# Private repo (token required)
package-checker --github-repo owner/private-repo --github-token ghp_xxx --source vulns.json
```

**Fetch only (no analysis):**
```bash
package-checker --github-org myorg --github-token ghp_xxx --github-only --github-output ./packages
```

**Automatically create GitHub issues for vulnerabilities:**
```bash
# Create one issue per vulnerable package
package-checker --github-org myorg --github-token ghp_xxx --source vulns.json --create-multiple-issues

# Create a single consolidated issue with all vulnerabilities
package-checker --github-repo owner/repo --github-token ghp_xxx --source vulns.json --create-single-issue
```

**Issue creation modes:**

| Flag | Description |
|------|-------------|
| `--create-multiple-issues` | Creates **one issue per vulnerable package**, each with detailed vulnerability info |
| `--create-single-issue` | Creates **one consolidated issue** containing all vulnerabilities in a single report |

Both modes include:

- Severity levels with visual indicators (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- Links to GHSA advisories and CVE details
- Affected files and versions
- Recommendations for remediation
- Automatic labeling with `security`, `vulnerability` and `dependencies` tags

**Note:** Both flags require a GitHub token with `repo` scope to create issues.

---

## 😎 Direct Package Lookup

You can check if a specific package or version is vulnerable **without needing a data source or scanning a project**:

```bash
# Check if a specific version is vulnerable
package-checker --package-name next --package-version 16.0.3

# Check with version ranges
package-checker --package-name lodash --package-version '^4.17.0'

# List all occurrences of a package in your project
package-checker --package-name express
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

- **[Why package-checker.sh?](docs/why.md)** — Learn why this tool exists and how it complements other vulnerability scanners
- **[Docker Usage](docs/docker.md)** — Complete guide to using Docker images
- **[Data Formats](docs/data-formats.md)** — Complete specification of JSON, CSV, PURL formats, per-ecosystem PURL shapes, and [known limitations](docs/data-formats.md#known-limitations)
- **[Vulnerability Feeds](docs/vulnerability-feeds.md)** — Guide to built-in GHSA/OSV feeds and generating custom feeds
- **[Vulnerability Scanning Tools](docs/vulnerability-scanning-tools.md)** — Guide to Trivy, Grype, Syft, OSV-Scanner, and other tools
- **[Configuration](docs/configuration.md)** — Detailed configuration reference
- **[GitHub Integration](docs/github.md)** — Advanced GitHub scanning features
- **[CI/CD Integration](docs/ci.md)** — Examples for GitHub Actions, GitLab CI, and more
- **[Testing](docs/testing.md)** — Testing guide with fixtures and examples
- **[Contributing](docs/contributing.md)** — Development workflow, commit conventions, and versioning
- **[AI Guide](docs/ai-guide.md)** — Structured reference for AI assistants to generate custom feeds, commands, and configs

### Use Cases

- **Security Teams**: Maintain internal vulnerability databases
- **Compliance**: Enforce company-specific security policies
- **CI/CD Pipelines**: Automated vulnerability checks
- **Incident Response**: Quick scans during security incidents
- **Supply Chain Security**: Monitor dependencies across multiple projects

## 🤖 AI-Assisted Usage

Use an AI assistant (Claude, ChatGPT, Copilot, etc.) to generate custom vulnerability feeds, CLI commands, and configuration files for package-checker.sh.

**Built-in help:**

```bash
# Show AI help menu with all options
package-checker --help-ai

# Output the system prompt — paste into any AI assistant
package-checker --help-ai prompt

# Output the full reference guide — schemas, validation, recipes
package-checker --help-ai doc

# Copy the prompt to clipboard (macOS)
package-checker --help-ai prompt | pbcopy
```

**What the AI can generate for you:**

- **Custom vulnerability feeds** in JSON, CSV, or PURL format — from a list of CVEs, package names, or security advisories
- **CLI commands** — the right flags for your specific use case (scanning, exporting, GitHub integration)
- **Configuration files** — `.package-checker.config.json` tailored to your project
- **CI/CD pipelines** — GitHub Actions, GitLab CI workflows with package-checker

**Example prompts you can give to an AI:**

```
"Generate a PURL vulnerability feed for these CVEs: CVE-2020-8203, CVE-2022-24999, CVE-2023-45133"
"Create a .package-checker.config.json that scans only production deps from our internal feed at https://security.company.com/feed.json"
"Write a GitHub Actions workflow that runs package-checker weekly and creates issues for new vulnerabilities"
"Block the package 'malicious-pkg' at all versions in a JSON feed"
```

**Available resources:**

- **[`prompt.md`](prompt.md)** — System prompt to inject into any AI assistant (paste as context or attach as file)
- **[`docs/ai-guide.md`](docs/ai-guide.md)** — Complete reference with schemas, validation rules, and generation recipes
- **`package-checker --help-ai`** — Condensed guide directly in your terminal

---

## 📄 License

MIT License — see the [`LICENSE`](LICENSE) file for details.

---

**Questions or issues?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).
