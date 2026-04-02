# AI Guide — Generating Custom Files for package-checker.sh

This document is a structured reference for AI assistants (Claude, ChatGPT, Copilot, etc.) to generate valid custom files, commands, and configurations for `package-checker.sh`.

Follow the schemas and rules below exactly. Every example is a valid, copy-pasteable snippet.

---

## Quick Reference

| What you want to generate | Format to use | Section |
|---|---|---|
| Custom vulnerability database | JSON, CSV, or PURL | [Vulnerability Feeds](#vulnerability-feed-schemas) |
| CLI command | bash | [CLI Command Builder](#cli-command-builder) |
| Configuration file | JSON | [Configuration File](#configuration-file-schema) |
| CI/CD pipeline | YAML | [CI/CD Templates](#cicd-templates) |
| Docker command | bash | [Docker Commands](#docker-commands) |

---

## Vulnerability Feed Schemas

### JSON Format

```jsonc
// SCHEMA: Each key is an npm package name (supports scoped packages like @scope/name)
// At least one of "versions" or "versions_range" is REQUIRED per entry
{
  "<package-name>": {
    "versions": ["<exact-version>", ...],          // Optional: array of exact vulnerable versions
    "versions_range": ["<range-expression>", ...], // Optional: array of semver range expressions
    "severity": "<critical|high|medium|low>",      // Optional: vulnerability severity
    "ghsa": "GHSA-xxxx-xxxx-xxxx",                 // Optional: GitHub Security Advisory ID
    "cve": "CVE-YYYY-NNNNN",                       // Optional: CVE identifier
    "source": "<string>"                           // Optional: source label (e.g. "internal", "ghsa", "osv")
  }
}
```

**Rules:**
- Keys are npm package names, including scoped (`@scope/package`)
- `versions` is an array of exact version strings: `["1.0.0", "1.0.1"]`
- `versions_range` is an array of semver range strings: `[">=1.0.0 <2.0.0"]`
- You can use both `versions` and `versions_range` in the same entry
- Metadata fields (`severity`, `ghsa`, `cve`, `source`) are optional but recommended
- File extension: `.json`

**Complete example:**

```json
{
  "express": {
    "versions": ["4.16.0", "4.16.1"],
    "versions_range": [">=4.0.0 <4.17.21"],
    "severity": "medium",
    "ghsa": "GHSA-rv95-896h-c2vc",
    "cve": "CVE-2022-24999",
    "source": "internal-audit"
  },
  "lodash": {
    "versions_range": [">=4.17.0 <4.17.21"],
    "severity": "high",
    "ghsa": "GHSA-p6mc-m468-83gw",
    "cve": "CVE-2020-8203",
    "source": "ghsa"
  },
  "@babel/traverse": {
    "versions_range": ["<7.23.2"],
    "severity": "critical",
    "ghsa": "GHSA-67hx-6x53-jw92",
    "cve": "CVE-2023-45133",
    "source": "ghsa"
  },
  "my-internal-lib": {
    "versions": ["2.0.0", "2.0.1", "2.1.0"],
    "severity": "high",
    "source": "security-team"
  }
}
```

---

### CSV Format

```csv
name,versions
<package-name>,<version-or-range>
```

**Rules:**
- First line MUST be the header: `name,versions`
- One entry per line
- If the version contains spaces or commas, wrap it in double quotes: `">=1.0.0 <2.0.0"`
- Scoped packages do NOT need quoting: `@babel/traverse,7.23.0`
- File extension: `.csv`

**Complete example:**

```csv
name,versions
express,4.16.0
express,4.16.1
lodash,">=4.17.0 <4.17.21"
@babel/traverse,"<7.23.2"
axios,">=0.18.0 <0.21.2"
ws,">=7.0.0 <7.4.6"
```

**With metadata columns (optional):**

```csv
name,versions,severity,ghsa,cve,source
express,4.16.0,medium,GHSA-rv95-896h-c2vc,CVE-2022-24999,ghsa
lodash,">=4.17.0 <4.17.21",high,GHSA-p6mc-m468-83gw,CVE-2020-8203,ghsa
```

---

### PURL Format (Recommended for Feeds)

```text
pkg:npm/<package-name>@<version-or-range>?<metadata-query-params>
```

**Rules:**
- One entry per line
- Lines starting with `#` are comments
- Empty lines are ignored
- Prefix: always `pkg:npm/`
- Scoped packages: `pkg:npm/@scope/name@version`
- Version ranges: `pkg:npm/express@>=4.0.0 <4.17.21`
- Metadata as URL query parameters: `?severity=high&ghsa=GHSA-xxx&cve=CVE-xxx&source=xxx`
- Available query parameters: `severity`, `ghsa`, `cve`, `source`
- File extension: `.purl`

**Complete example:**

```text
# Internal vulnerability feed
# Generated: 2026-04-02

# Critical
pkg:npm/@babel/traverse@<7.23.2?severity=critical&ghsa=GHSA-67hx-6x53-jw92&cve=CVE-2023-45133&source=internal

# High
pkg:npm/lodash@>=4.17.0 <4.17.21?severity=high&ghsa=GHSA-p6mc-m468-83gw&cve=CVE-2020-8203&source=ghsa
pkg:npm/minimist@<1.2.6?severity=high&ghsa=GHSA-xvch-5gv4-984h&cve=CVE-2021-44906&source=osv

# Medium
pkg:npm/express@>=4.0.0 <4.17.21?severity=medium&ghsa=GHSA-rv95-896h-c2vc&cve=CVE-2022-24999&source=ghsa
pkg:npm/axios@>=0.18.0 <0.21.2?severity=medium&ghsa=GHSA-4w2v-q235-vp99&cve=CVE-2020-28168&source=ghsa

# Low — internal packages
pkg:npm/my-internal-lib@2.0.0?severity=low&source=security-team
pkg:npm/my-internal-lib@2.0.1?severity=low&source=security-team
```

---

## Version Range Syntax

Use these operators in `versions_range` (JSON) or directly in PURL/CSV version fields:

| Syntax | Meaning | Example |
|---|---|---|
| `1.2.3` | Exact version | `1.2.3` |
| `>=1.0.0 <2.0.0` | Greater/less than | All 1.x versions |
| `>1.0.0` | Strictly greater than | Above 1.0.0 |
| `<=2.0.0` | Less than or equal | Up to 2.0.0 |
| `<7.23.2` | Strictly less than | Below 7.23.2 |
| `~1.2.3` | Tilde range | `>=1.2.3 <1.3.0` |
| `^1.2.3` | Caret range | `>=1.2.3 <2.0.0` |
| `*` | Any version | All versions |

**Combining operators:** separate with a space within the same string: `">=1.0.0 <2.0.0"`

---

## CLI Command Builder

### Command Structure

```bash
package-checker [PATH] [OPTIONS]
```

- `PATH` is optional, defaults to current directory (`.`)
- Options can be combined freely

### Common Command Patterns

**Scan current directory with built-in feeds:**

```bash
# GHSA only (default)
package-checker

# GHSA + OSV (recommended for comprehensive coverage)
package-checker --default-source-ghsa-osv

# OSV only
package-checker --default-source-osv
```

**Scan with custom vulnerability file:**

```bash
# Local file (format auto-detected from extension)
package-checker --source ./my-vulns.json
package-checker --source ./my-vulns.csv
package-checker --source ./my-vulns.purl

# Remote URL
package-checker --source https://example.com/vulns.json

# Multiple sources
package-checker --source ./internal.json --source ./external.purl

# Built-in + custom
package-checker --default-source-ghsa-osv --source ./internal.json
```

**Check a specific package:**

```bash
# Check if a version is vulnerable (uses default GHSA feed)
package-checker --package-name <name> --package-version <version>

# Examples
package-checker --package-name express --package-version 4.17.1
package-checker --package-name lodash --package-version "^4.17.0"
package-checker --package-name @babel/traverse --package-version 7.23.0

# With custom source
package-checker --source ./vulns.json --package-name express --package-version 4.16.0
```

**Filter what gets scanned:**

```bash
# Only lockfiles
package-checker --only-lockfiles

# Only package.json
package-checker --only-package-json

# Specific lockfile types (npm, yarn, pnpm, bun, deno)
package-checker --lockfile-types yarn,npm
package-checker --only-lockfiles --lockfile-types pnpm
```

**Export results:**

```bash
# JSON export
package-checker --default-source-ghsa-osv --export-json results.json

# CSV export
package-checker --default-source-ghsa-osv --export-csv results.csv

# Both
package-checker --default-source-ghsa-osv --export-json results.json --export-csv results.csv
```

**GitHub integration:**

```bash
# Scan organization
package-checker --github-org <org> --github-token $GITHUB_TOKEN --default-source-ghsa-osv

# Scan single repo
package-checker --github-repo owner/repo --github-token $GITHUB_TOKEN --default-source-ghsa-osv

# Create issues for found vulnerabilities
package-checker --github-repo owner/repo --github-token $GITHUB_TOKEN --default-source-ghsa-osv --create-single-issue
package-checker --github-org myorg --github-token $GITHUB_TOKEN --default-source-ghsa-osv --create-multiple-issues
```

**Fetch/update vulnerability feeds:**

```bash
# Fetch all feeds
package-checker --fetch-all ./data

# Fetch individual feeds
package-checker --fetch-ghsa ./data/ghsa.purl
package-checker --fetch-osv ./data/osv.purl
```

### All Available Flags

| Flag | Argument | Description |
|---|---|---|
| `-h`, `--help` | — | Show help |
| `-v`, `--version` | — | Show version |
| `--help-ai` | — | Show AI generation guide |
| `-s`, `--source` | `PATH\|URL` | Vulnerability source (repeatable) |
| `--default-source-ghsa` | — | Use built-in GHSA feed |
| `--default-source-osv` | — | Use built-in OSV feed |
| `--default-source-ghsa-osv` | — | Use both feeds (recommended) |
| `-f`, `--format` | `FORMAT` | Force format: json, csv, purl, sarif, sbom-cyclonedx, trivy-json |
| `--csv-columns` | `COLS` | CSV column mapping: `"name,versions"` or `"1,2"` |
| `--package-name` | `NAME` | Check specific package |
| `--package-version` | `VER` | Check specific version (requires `--package-name`) |
| `-c`, `--config` | `FILE` | Config file path |
| `--no-config` | — | Skip config file |
| `--export-json` | `FILE` | Export results to JSON |
| `--export-csv` | `FILE` | Export results to CSV |
| `--github-org` | `ORG` | Scan GitHub organization |
| `--github-repo` | `owner/repo` | Scan GitHub repository |
| `--github-token` | `TOKEN` | GitHub token |
| `--github-output` | `DIR` | Output dir for fetched files |
| `--github-only` | — | Only fetch from GitHub |
| `--create-multiple-issues` | — | One issue per vulnerable package |
| `--create-single-issue` | — | Single consolidated issue |
| `--fetch-all` | `DIR` | Fetch all feeds to directory |
| `--fetch-osv` | `FILE` | Fetch OSV feed |
| `--fetch-ghsa` | `FILE` | Fetch GHSA feed |
| `--only-package-json` | — | Skip lockfiles |
| `--only-lockfiles` | — | Skip package.json |
| `--lockfile-types` | `TYPES` | Comma-separated: npm,yarn,pnpm,bun,deno |

---

## Configuration File Schema

File: `.package-checker.config.json` (project root)

```jsonc
{
  // SOURCES — vulnerability databases to load
  // Use this for custom/internal sources. For built-in GHSA/OSV feeds, prefer CLI flags instead.
  "sources": [
    {
      "source": "<path-or-url>",     // REQUIRED: file path or URL
      "format": "<format>",          // Optional: json|csv|purl|sarif|sbom-cyclonedx|trivy-json (auto-detected)
      "name": "<display-name>",      // Optional: human-readable label
      "columns": "<col1,col2>"       // Optional: CSV column mapping
    }
  ],

  // GITHUB — remote scanning settings
  "github": {
    "org": "<organization-name>",    // Optional: GitHub org to scan
    "repo": "<owner/repo>",          // Optional: single repo to scan
    "token": "<github-token>",       // Optional: PAT (prefer GITHUB_TOKEN env var)
    "output": "./packages"           // Optional: output dir for fetched files
  },

  // OPTIONS — scan behavior
  "options": {
    "ignore_paths": [                // Optional: directories to skip
      "node_modules",
      ".yarn",
      ".git",
      "dist"
    ],
    "dependency_types": [            // Optional: which sections to check in package.json
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies"
    ]
  }
}
```

**Rules:**
- All sections are optional
- CLI flags override config file values
- Format is auto-detected from file extension if omitted
- For built-in feeds, use `--default-source-ghsa-osv` on CLI instead of hardcoding paths
- Token can be set via `GITHUB_TOKEN` env var instead of config

**Example — internal security team config:**

```json
{
  "sources": [
    {
      "source": "https://security.internal.company.com/api/vulns.json",
      "name": "Internal Security DB"
    },
    {
      "source": "./custom-blocklist.purl",
      "format": "purl",
      "name": "Blocked Packages"
    }
  ],
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git", "dist", "build", "__tests__"],
    "dependency_types": ["dependencies", "optionalDependencies"]
  }
}
```

---

## CI/CD Templates

### GitHub Actions

```yaml
name: Security Check

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 1'  # Weekly

jobs:
  vulnerability-check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-osv: true
      fail-on-vulnerabilities: true
```

### GitHub Actions (manual setup)

```yaml
name: Vulnerability Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install package-checker
        run: |
          curl -sS -o package-checker https://raw.githubusercontent.com/maxgfr/package-checker.sh/main/script.sh
          chmod +x package-checker

      - name: Run scan
        run: ./package-checker --default-source-ghsa-osv --export-json results.json

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnerability-report
          path: results.json
```

### GitLab CI

```yaml
vulnerability-scan:
  image: ghcr.io/maxgfr/package-checker.sh:latest
  script:
    - package-checker --default-source-ghsa-osv --export-json results.json
  artifacts:
    paths:
      - results.json
    when: always
```

---

## Docker Commands

```bash
# Scan current directory (default GHSA feed)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest

# Comprehensive scan
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa-osv

# With custom source file (mount it)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --source /workspace/my-vulns.json

# Export results
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa-osv --export-json /workspace/results.json

# Scan subdirectory
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest /workspace/my-app --default-source-ghsa-osv
```

---

## Generation Recipes

Common tasks an AI might be asked to do, with step-by-step instructions.

### "Create a vulnerability blocklist for internal packages"

1. Choose format: **JSON** for rich metadata, **PURL** for simplicity
2. List each package with its vulnerable versions or ranges
3. Add severity and source metadata
4. Save as `internal-vulns.json` or `internal-vulns.purl`
5. Use: `package-checker --source ./internal-vulns.json`

### "Set up security scanning in CI"

1. Use the reusable workflow for zero-config setup
2. Or install manually and run with `--default-source-ghsa-osv`
3. Add `--export-json` for artifact upload
4. Use `--create-single-issue` with `--github-token` for auto-issue creation

### "Block a package at all versions"

```json
{
  "dangerous-package": {
    "versions_range": ["*"],
    "severity": "critical",
    "source": "security-policy"
  }
}
```

Or in PURL:

```text
pkg:npm/dangerous-package@*?severity=critical&source=security-policy
```

### "Check if we're affected by a specific CVE"

```bash
# Create a minimal feed for that CVE
echo 'pkg:npm/affected-package@>=1.0.0 <1.5.3?severity=high&cve=CVE-YYYY-NNNNN' > /tmp/cve-check.purl

# Scan your project
package-checker --source /tmp/cve-check.purl
```

### "Generate a feed from a list of package@version pairs"

Given input like:
```
express@4.16.0
lodash@4.17.20
axios@0.21.0
```

Generate PURL:
```text
pkg:npm/express@4.16.0?severity=unknown&source=manual
pkg:npm/lodash@4.17.20?severity=unknown&source=manual
pkg:npm/axios@0.21.0?severity=unknown&source=manual
```

### "Scan only production dependencies"

```json
{
  "options": {
    "dependency_types": ["dependencies"],
    "ignore_paths": ["node_modules", ".git", "test", "__tests__"]
  }
}
```

```bash
package-checker --config .package-checker.config.json --default-source-ghsa-osv --only-lockfiles
```

---

## Validation Checklist

Before outputting a generated file, verify:

- [ ] JSON files are valid JSON (no trailing commas, proper quoting)
- [ ] CSV files have a header row (`name,versions` minimum)
- [ ] PURL lines start with `pkg:npm/`
- [ ] Version ranges use proper semver operators (`>=`, `<`, `>`, `<=`, `~`, `^`)
- [ ] Scoped packages use `@scope/name` format
- [ ] GHSA IDs match pattern `GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`
- [ ] CVE IDs match pattern `CVE-\d{4}-\d{4,}`
- [ ] Severity is one of: `critical`, `high`, `medium`, `low`
- [ ] File extensions match format: `.json`, `.csv`, `.purl`
- [ ] Config file is named `.package-checker.config.json`
