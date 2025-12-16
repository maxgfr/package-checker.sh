# Continuous Integration examples

This page contains CI snippets for running `package-checker.sh` in common CI systems.

**Note:** package-checker.sh includes built-in vulnerability feeds (GHSA and OSV) in the `data/` folder. You can use these feeds directly in CI without fetching external sources, or use Docker images that include the feeds.

## GitHub Actions

### Reusable Workflow (Recommended)

This repository provides a reusable GitHub Actions workflow for automated vulnerability scanning.

#### Basic Usage

Add this to your `.github/workflows/security-check.yml`:

```yaml
name: Security Check

on:
  push:
    branches: [ main ]
  pull_request:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  vulnerability-check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      source: 'https://your-domain.com/vulnerabilities.json'
      fail-on-vulnerabilities: true
```

#### Workflow Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `source` | Vulnerability source URL or path (JSON or CSV) | Yes | - |
| `source-format` | Format of the source (`json` or `csv`) | No | Auto-detected |
| `csv-columns` | CSV column mapping | No | `name,versions` |
| `working-directory` | Directory to scan | No | `.` |
| `fail-on-vulnerabilities` | Fail workflow if vulnerabilities found | No | `true` |
| `script-version` | Version/branch of script to use | No | `main` |
| `additional-args` | Extra arguments for the script | No | - |

#### Advanced Examples

**Check with CSV source:**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      source: 'https://example.com/vulns.csv'
      source-format: 'csv'
      csv-columns: 'name,versions'
```

**Check specific directory:**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      source: './vulnerabilities.json'
      working-directory: './packages/frontend'
```

**Check without failing (report only):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      source: 'https://example.com/vulns.json'
      fail-on-vulnerabilities: false
```

**Multiple sources with custom config:**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      source: 'https://example.com/vulns1.json'
      additional-args: '--source https://example.com/vulns2.csv --config .package-checker.config.json'
```

See [`.github/workflows/example-usage.yml`](../.github/workflows/example-usage.yml) for more examples.

### Using Docker Images

The easiest way to use package-checker.sh in CI with built-in feeds:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for vulnerabilities with built-in GHSA feed
        run: |
          docker run -v ${{ github.workspace }}:/workspace \
            ghcr.io/maxgfr/package-checker.sh:latest \
            --source data/ghsa.purl
```

### Manual Script Execution

If you prefer not to use the Docker image, you can clone the repo and run the script:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: project

      - name: Clone package-checker.sh
        uses: actions/checkout@v4
        with:
          repository: maxgfr/package-checker.sh
          path: package-checker

      - name: Check for vulnerabilities with built-in feeds
        working-directory: project
        run: |
          ../package-checker/script.sh --source ../package-checker/data/ghsa.purl

      - name: Or use custom source
        working-directory: project
        run: |
          curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://your-domain.com/vulns.json
```

To use a private vulnerability source or to increase GitHub API rate limits, supply a token:

```yaml
- name: Check with private source
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://internal/vulns.json
```

## GitLab CI

### Using Docker Image (Recommended)

Example using the official Docker image with built-in feeds:

```yaml
vulnerability-check:
  image: ghcr.io/maxgfr/package-checker.sh:latest
  script:
    - package-checker --source data/ghsa.purl

# Or use lightweight image and fetch feeds
vulnerability-check-lite:
  image: ghcr.io/maxgfr/package-checker.sh:lite
  script:
    - package-checker --fetch-ghsa data/ghsa.purl
    - package-checker --source data/ghsa.purl
```

### Manual Installation

Example for GitLab CI using the `ubuntu:latest` image:

```yaml
vulnerability-check:
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl git
    - git clone https://github.com/maxgfr/package-checker.sh.git /tmp/checker
  script:
    - /tmp/checker/script.sh --source /tmp/checker/data/ghsa.purl
```

## Tips for CI

- **Use Docker images for simplicity**: The official Docker images include built-in vulnerability feeds, making setup easier
  - Full image: `ghcr.io/maxgfr/package-checker.sh:latest` (~14MB with GHSA and OSV feeds)
  - Lightweight: `ghcr.io/maxgfr/package-checker.sh:lite` (~8MB, bring your own data)
- **Use built-in feeds for zero-setup scanning**: The `data/ghsa.purl` and `data/osv.purl` feeds are automatically updated and ready to use
- Store secrets (GitHub tokens, private URLs) in the CI provider's secret store and reference them as environment variables
- If you only want to fetch packages from GitHub (without scanning), use `--github-only` and `--github-output` to save files for later inspection
- For reproducible results, pin the Docker image to a specific tag or pin the `script.sh` URL to a commit SHA instead of `refs/heads/main`
