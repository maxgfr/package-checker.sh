# package-checker.sh

A flexible, lightweight shell script to detect vulnerable npm packages against custom vulnerability databases. Check your Node.js projects for known vulnerable package versions using your own data sources.

## 🚀 Features

- **Custom Data Sources**: Configure your own vulnerability lists (JSON or CSV format)
- **Automatic Format Detection**: Detects JSON/CSV from file extensions
- **Multiple Sources**: Combine multiple vulnerability databases in one scan
- **Multiple Package Managers**: Supports npm, Yarn, pnpm, and Bun
- **Recursive Scanning**: Finds all lockfiles and package.json files in subdirectories
- **Respects .gitignore**: Automatically excludes ignored files
- **Monorepo-Friendly**: Perfect for projects with multiple packages
- **Flexible Configuration**: Use command-line arguments or configuration files
- **Color-Coded Output**: Easy-to-read results with visual highlighting

## 📋 Prerequisites

- **jq** (required): JSON parser

  - macOS: `brew install jq`
  - Ubuntu/Debian: `apt-get install jq`

- **yq** (optional): Better YAML parsing for pnpm-lock.yaml
  - macOS: `brew install yq`
  - Ubuntu/Debian: `snap install yq`

## 🎯 Quick Start

### With Configuration File

1. Create a [`.package-checker-config.json`](.package-checker-config.json) file in your project:

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
./script.sh --url https://your-domain.com/vulnerabilities.json

# Or with CSV
./script.sh --url https://your-domain.com/vulnerabilities.csv

# You can also specify format explicitly if needed
./script.sh --url https://your-domain.com/vulnerabilities.json --format json
```

### With Configuration File

Create a [`.package-checker-config.json`](.package-checker-config.json) file:

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
    -u, --url URL           Data source URL (can be used multiple times)
    -f, --format FORMAT     Data format: json or csv (optional, auto-detected from extension)
    -c, --config FILE       Path to configuration file
    --no-config             Skip loading configuration file
```

### Examples

#### Multiple Data Sources

```bash
# Format is auto-detected from file extensions
./script.sh \
  --url https://source1.com/vulns.json \
  --url https://source2.com/vulns.csv

# Or specify formats explicitly
./script.sh \
  --url https://source1.com/data --format json \
  --url https://source2.com/data --format csv
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
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --url https://your-domain.com/vulnerabilities.json
```

With multiple sources:

```bash
curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --url https://example.com/vulns1.json --url https://example.com/vulns2.csv
```

## 📊 Data Source Formats

### JSON Format

The script expects a JSON object where keys are package names and values contain vulnerability information:

```json
{
  "package-name": {
    "vuln_vers": ["1.0.0", "2.0.0", "2.1.0"]
  },
  "@scope/another-package": {
    "vuln_vers": ["3.0.0"]
  }
}
```

### CSV Format

Simple comma-separated format with package name and version:

```csv
package_name,package_version
express,4.16.0
express,4.16.1
lodash,4.17.19
@scope/scoped-package,1.5.0
```

**Notes:**

- First line is a header (will be ignored if it contains column names)
- Whitespace is automatically trimmed
- Supports scoped packages (`@scope/package`)
- Column headers: `package_name,package_version`

## ⚙️ Configuration File

Create a [`.package-checker-config.json`](.package-checker-config.json) in your project root:

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

### package.json Files (dependency checking)

- `dependencies`
- `devDependencies`
- `optionalDependencies`
- `peerDependencies`

All files are found recursively while respecting [`.gitignore`](script.sh:488) rules.

## 📤 Output

### Color Coding

- ✅ **Green**: No vulnerabilities or informational messages
- ⚠️ **Red**: Vulnerable packages found (exact version match)
- ⚠️ **Yellow**: Package in vulnerability list (check lockfile for version)
- 🔍 **Blue**: Informational messages

### Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected

Perfect for CI/CD pipelines:

```bash
./script.sh || exit 1
```

### Example Output

```
╔════════════════════════════════════════════════════╗
║       Package Vulnerability Checker                ║
╚════════════════════════════════════════════════════╝

🔍 Loading: Company Security Database
   URL: https://example.com/vulnerabilities.json
   Format: json
✅ Loaded 150 packages from Company Security Database

🔍 Loading: External Vulnerability Database
   URL: https://security.example.com/npm-vulns.json
   Format: json
✅ Loaded 45 packages from External Vulnerability Database

📊 Total unique vulnerable packages: 185

🔍 Searching for all lockfiles in the project (respecting .gitignore)...
✅ 3 lockfile(s) found

📋 List of found lockfiles:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📁 ./
     └─ package-lock.json
  📁 ./packages/frontend
     └─ yarn.lock
  📁 ./packages/backend
     └─ pnpm-lock.yaml
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔎 Starting lockfiles analysis...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📂 Folder: ./packages/frontend
📄 File: ./packages/frontend/yarn.lock
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Analyzing ./packages/frontend/yarn.lock...
⚠️  [./packages/frontend/yarn.lock] vulnerable-package@1.0.0 (vulnerable)

=============================
⚠️  WARNING: Vulnerable packages have been detected

Vulnerable packages found:

📄 File: ./packages/frontend/yarn.lock
   └─ vulnerable-package@1.0.0

Recommendations:
   - Update to versions not listed in your vulnerability databases
   - Check your CI/CD pipeline and generated artifacts
=============================
```

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

      - name: Install jq
        run: sudo apt-get install -y jq

      - name: Check for vulnerabilities
        run: |
          curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

### GitLab CI

```yaml
vulnerability-check:
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y jq curl
  script:
    - curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

### Custom Configuration in CI

```yaml
- name: Check vulnerabilities with custom source
  run: |
    ./script.sh \
      --url https://company.internal/vulns.json \
      --format json
```

## 🎨 Advanced Usage

### Multiple Sources with Priority

Combine multiple vulnerability databases - the script merges all sources:

```bash
./script.sh \
  --url https://primary-source.com/vulns.json \
  --url https://secondary-source.com/vulns.csv \
  --url https://third-source.com/vulns.json
```

### Custom Config Location

```bash
./script.sh --config ./security/vulnerability-sources.json
```

### Skip Config File

```bash
./script.sh --no-config --url https://direct-source.com/vulns.json
```

## 🛠️ Creating Your Own Vulnerability Database

### JSON Format

Host a JSON file with this structure (see [`example-vulnerabilities.json`](example-vulnerabilities.json)):

```json
{
  "express": {
    "vuln_vers": ["4.16.0", "4.16.1", "4.17.0"]
  },
  "lodash": {
    "vuln_vers": ["4.17.19", "4.17.20", "4.17.21"]
  },
  "@types/node": {
    "vuln_vers": ["14.0.0", "14.0.1"]
  }
}
```

### CSV Format

Create a CSV file (see [`example-vulnerabilities.csv`](example-vulnerabilities.csv)):

```csv
package_name,package_version
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
./script.sh --url https://your-domain.com/vulnerabilities.csv

# Or test locally with example files
./script.sh --url file://$(pwd)/example-vulnerabilities.json
./script.sh --url file://$(pwd)/example-vulnerabilities.csv
```

## 📚 Use Cases

- **Security Teams**: Maintain internal vulnerability databases
- **Compliance**: Check against company-specific security policies
- **Incident Response**: Quickly scan projects during security incidents
- **Continuous Monitoring**: Integrate into CI/CD for automated checks
- **Supply Chain Security**: Track vulnerable dependencies across multiple projects
- **Custom Threat Intelligence**: Use proprietary vulnerability data

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Report bugs
- Suggest features
- Submit pull requests
- Share your vulnerability database formats

## 📝 License

MIT

## 🙏 Credits

Created and maintained by [@maxgfr](https://github.com/maxgfr)

## 📞 Support

- GitHub Issues: [maxgfr/package-checker.sh](https://github.com/maxgfr/package-checker.sh/issues)
- Repository: [maxgfr/package-checker.sh](https://github.com/maxgfr/package-checker.sh)

---

**⚠️ Security Note**: Always verify the integrity of data sources before using them. Use HTTPS URLs and trusted sources for vulnerability data.
