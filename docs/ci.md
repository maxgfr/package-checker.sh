# Continuous Integration examples

This page contains CI snippets for running `package-checker.sh` in common CI systems.

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
| `csv-columns` | CSV column mapping | No | `package_name,package_versions` |
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
      csv-columns: 'package_name,package_versions'
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

### Manual Script Execution

If you prefer not to use the reusable workflow, you can run the script directly:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for vulnerabilities
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

Example for GitLab CI using the `ubuntu:latest` image:

```yaml
vulnerability-check:
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl
  script:
    - curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
```

## Tips for CI

- Store secrets (GitHub tokens, private URLs) in the CI provider's secret store and reference them as environment variables.
- If you only want to fetch packages from GitHub (without scanning), use `--github-only` and `--github-output` to save files for later inspection.
- For reproducible results, pin the `script.sh` URL to a commit SHA instead of `refs/heads/main`.
