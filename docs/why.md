# Why package-checker.sh?

## The Problem

You're right - there are thousands of vulnerability scanning tools out there. So why another one?

**The answer is simple:** `package-checker.sh` doesn't compete with those tools. It **complements** them.

## What Makes package-checker.sh Different

### 1. Custom Vulnerability Database Support + Built-in Data Feeds

**package-checker.sh** gives you the best of both worlds: it comes with **built-in vulnerability feeds** (GHSA and OSV) for immediate use, while also supporting **your own custom** vulnerability databases.

Why is this useful?

- **Ready to use**: Pre-generated vulnerability feeds (GHSA and OSV) included in the repository - scan immediately with 200,000+ npm vulnerabilities
- **Auto-updated feeds**: Vulnerability data automatically refreshed every 12 hours via GitHub Actions
- **Documentation**: See the [README](README.md) for quick start guides and detailed usage examples
- **Internal security policies**: Maintain your own list of packages you want to ban or flag
- **Custom CVE tracking**: Track specific vulnerabilities relevant to your organization
- **Compliance requirements**: Enforce company-specific security rules
- **Private vulnerability data**: Use proprietary or internal vulnerability databases

You can use the included data feeds (in `data/` folder) or bring your own data sources (JSON, CSV, PURL, SARIF, SBOM), and the tool checks your projects against them.

### 2. Direct Package Lookup (No Project Scanning Required)

Check if a package is vulnerable **without scanning a project**:

```bash
# Check if a specific version is vulnerable
package-checker --package-name next --package-version 16.0.3

# Check with version ranges
package-checker --package-name express --package-version '^4.17.0'

# List where a package is used
package-checker --package-name lodash
```

This is perfect for:

- Pre-installation checks: "Is this version safe before I `npm install`?"
- Security research: "Which versions of this package are vulnerable?"
- Dependency investigation: "Where is this package used in my projects?"

### 3. GitHub Organization-First Design

Scan entire organizations or specific repositories:

- **Multi-repository support**: Check vulnerabilities across your entire GitHub organization
- **Automated issue creation**: Create GitHub issues directly on repositories with vulnerabilities
- **PURL integration**: Uses Package URL (PURL) format for precise package identification
- **GitHub Actions native**: Built specifically for CI/CD pipelines

```bash
# Scan your entire organization
package-checker --github-org mycompany --source vulns.json

# Create one issue per vulnerable package
package-checker --github-org mycompany --source vulns.json --create-multiple-issues

# Create a single consolidated security report
package-checker --github-repo owner/repo --source vulns.json --create-single-issue
```

### 4. Ultra-Lightweight & Blazing Fast

- **Pure Bash**: No Python runtime, no Node.js dependencies, no Go binaries
- **AWK-powered parsing**: Uses AWK for JSON parsing - exponentially faster than jq or Python
- **Minimal footprint**: Single shell script, ~100KB, runs anywhere bash is available
- **No installation**: Just download and run - no `pip install`, `npm install`, or complex setup
- **Docker images available**:
  - Full version (~43MB) with GHSA and OSV feeds included
  - Lightweight version (~27MB) bring-your-own-data

**Performance comparison** (parsing a 500KB SARIF file):

- package-checker.sh (AWK): ~50ms
- Python-based tools: ~500ms+
- Node.js-based tools: ~300ms+

**Scanning against large datasets** (200,000+ vulnerabilities from OSV/GHSA):

- package-checker.sh: ~200ms for average project
- Thanks to AWK-powered parsing and optimized algorithms

### 5. Format Agnostic

Works with **any** vulnerability data format:

- **JSON**: Custom vulnerability databases
- **CSV**: Simple spreadsheet-based lists
- **PURL**: Package URL format for standardized package identification
- **SARIF**: Static analysis results from Trivy, Semgrep, OSV-Scanner, etc.
- **SBOM CycloneDX**: Software Bill of Materials from Syft, Grype, Trivy
- **Trivy JSON**: Native Trivy output format

You bring the data, the tool does the checking.

### 6. Zero Dependencies Philosophy

```bash
# What you need
bash
awk (GNU awk or mawk)
curl (for GitHub API and remote data sources)

# That's it. No:
- Python + pip packages
- Node.js + npm modules
- Complex build systems
```

This means:

- Works on bare metal servers
- Runs in minimal Docker images (~27MB lightweight, ~43MB with data feeds)
- Perfect for air-gapped environments (use included data feeds)
- No dependency hell

### 7. Smart Defaults, Full Control

**Zero-config usage with built-in data:**
```bash
# Use included GHSA feed (no setup required!)
package-checker --source data/ghsa.purl

# Or use both OSV and GHSA feeds
package-checker --source data/osv.purl --source data/ghsa.purl
```

**Or use external/custom sources:**
```bash
# Point it at a custom report
package-checker --source vulnerabilities.sarif

# Mix built-in and custom sources
package-checker --source data/ghsa.purl --source custom-vulns.json
```

**Advanced customization:**
```bash
# Configuration file support
cat > .package-checker.config.json <<EOF
{
  "sources": [
    {"source": "data/ghsa.purl", "format": "purl"},
    {"source": "https://...", "format": "sarif"},
    {"source": "./local.json", "format": "trivy-json"}
  ],
  "github": {
    "org": "your-org",
    "create_issues": true
  }
}
EOF

package-checker  # Uses config automatically
```

## Real-World Use Cases

### Use Case 1: Organization-Wide CVE Response

**Scenario:** A critical CVE in `lodash` is announced.

**Traditional approach:**
1. Run scanner on each repo manually
2. Parse reports manually
3. Create tracking issues manually
4. Update spreadsheet of affected repos

**With package-checker.sh:**
```bash
package-checker \
  --package-name lodash \
  --github-org mycompany \
  --create-multiple-issues
```

**Result:** Issues created in all affected repos in seconds.

### Use Case 2: Multi-Source Vulnerability Analysis

**Scenario:** You want comprehensive coverage using multiple vulnerability sources (built-in feeds + custom data + scanner outputs).

**Traditional approach:**
- Different tools for each format
- Manual correlation
- Complex scripting

**With package-checker.sh:**
```json
{
  "sources": [
    {"source": "data/ghsa.purl", "format": "purl"},
    {"source": "data/osv.purl", "format": "purl"},
    {"source": "https://cdn/trivy.json", "format": "trivy-json"},
    {"source": "./custom-vulns.csv", "format": "csv"}
  ]
}
```

**Result:** Single unified check across all sources - built-in feeds + custom data + scanner results.

### Use Case 3: Minimal CI/CD Footprint

**Scenario:** You want vulnerability checks in CI but don't want to install heavy dependencies.

**Traditional approach:**
```dockerfile
FROM ubuntu
RUN apt-get update && apt-get install -y python3 pip nodejs npm
RUN pip install trivy-operator safety bandit
RUN npm install -g snyk audit-ci
# Image size: 800MB+
```

**With package-checker.sh:**
```dockerfile
# Use the official Docker image with vulnerability feeds included
FROM ghcr.io/maxgfr/package-checker.sh:latest
# Image size: 43MB (includes GHSA and OSV feeds!)

# Or use the lightweight version and fetch/bring your own data
FROM ghcr.io/maxgfr/package-checker.sh:lite
# Image size: 27MB (bring-your-own-data)
```

## What package-checker.sh Is NOT

Let's be clear about what this tool doesn't do:

- **Does NOT discover new vulnerabilities** - It checks against existing vulnerability databases (built-in GHSA/OSV feeds or your custom sources)
- **Does NOT generate SARIF/SBOM** - Use Syft, Trivy, Semgrep, etc. for that (but it can consume their outputs!)
- **Does NOT fix vulnerabilities** - It helps you find and track them

## The Philosophy

> "Do one thing and do it well" - Unix Philosophy

`package-checker.sh` does **one thing**:

**Check your projects against vulnerability databases (built-in or custom), with support for direct package lookups and GitHub organization scanning.**

It's the missing piece for:

1. **Instant vulnerability scanning** - Use built-in GHSA/OSV feeds with 200,000+ vulnerabilities - no setup required
2. **Custom vulnerability tracking** - Add your own vulnerability lists on top of public databases
3. **Quick package checks** - Verify if a package version is safe before installing
4. **Organization-wide enforcement** - Ensure all repos comply with your security policies

## Quick Comparison

| Feature | package-checker.sh | Trivy | OSV-Scanner | Snyk | Grype |
|---------|-------------------|-------|-------------|------|-------|
| Built-in vuln feeds | **Yes (GHSA+OSV)** | Yes | Yes (OSV) | Yes | Yes |
| Custom vuln DB | **Yes** | No | No | No | No |
| Direct package lookup | **Yes** | No | No | No | No |
| Checks GitHub org | **Yes** | No | No | No | No |
| Creates issues | **Yes** | No | No | Limited | No |
| Multi-format input | **Yes** | No | No | No | No |
| Zero dependencies | **Yes** | No | No | No | No |
| Speed (parsing) | **~50ms** | N/A | N/A | N/A | N/A |
| Size | **~100KB script** | ~100MB | ~50MB | ~200MB | ~80MB |

## Getting Started

```bash
# 1. Install package-checker.sh
brew install maxgfr/tap/package-checker

# 2. Scan your project with built-in GHSA feed (200,000+ vulnerabilities!)
package-checker --source data/ghsa.purl

# 3. Or use Docker image with feeds included
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --source /app/data/ghsa.purl

# 4. Check if a specific version is vulnerable
package-checker --package-name express --package-version 4.17.1 --source data/ghsa.purl

# 5. Check with version ranges
package-checker --package-name lodash --package-version '^4.17.0' --source data/ghsa.purl

# 6. Scan your entire GitHub organization
package-checker --source data/ghsa.purl --github-org mycompany --github-token $GITHUB_TOKEN

# 7. Add your own custom vulnerability database
package-checker --source data/ghsa.purl --source custom-vulns.json
```

## Conclusion

**Use package-checker.sh if you want:**

- **Built-in vulnerability feeds** - Start scanning immediately with 200,000+ vulnerabilities from GHSA and OSV
- **Custom vulnerability databases** - Add your own lists to track packages you want to ban or flag
- **Direct package lookups** - Quick checks without scanning projects
- **Organization-wide enforcement** - Scan entire GitHub orgs
- **Multi-format support** - JSON, CSV, PURL, SARIF, SBOM (mix and match!)
- **Semver range support** - `~`, `^`, `>=`, `<`, `*` all work
- **Zero dependencies** - Just bash, awk, and curl
- **Lightning-fast** - AWK-powered parsing, ~50ms for 500KB files
- **Automated issue creation** - Create GitHub issues on vulnerable repos
- **Minimal Docker images** - 27MB lightweight or 43MB with feeds included

**Don't use package-checker.sh if you want:**

- **Vulnerability discovery** - Use Trivy, OSV-Scanner, Grype, Snyk to discover new vulnerabilities
- **SBOM generation** - Use Syft, Trivy, etc. for that (but you can use their output with package-checker!)
- **Vulnerability remediation** - Use Dependabot or Renovate for automated fixes

---

**Questions?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).

**Want to contribute?** PRs welcome!
