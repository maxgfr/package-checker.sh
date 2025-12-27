# Continuous Integration examples

This page contains CI snippets for running `package-checker.sh` in common CI systems.

**Note:** package-checker.sh includes built-in vulnerability feeds (GHSA and OSV) in the `data/` folder. You can use these feeds directly in CI without fetching external sources, or use Docker images that include the feeds.

**Command Reference:** When installed via Homebrew, the command is `package-checker`. When using the script directly, it's `./script.sh`. This documentation uses `./script.sh` for script examples and `package-checker` for Homebrew examples.

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
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  vulnerability-check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      fail-on-vulnerabilities: true
```

This example uses the built-in GHSA feed from the `data/` folder. You can also:

- Use `use-osv: true` for the OSV feed
- Use both feeds with `use-ghsa: true` and `use-osv: true`
- Provide your own custom vulnerability source URL with `source:`

#### Workflow Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `use-ghsa` | Use built-in GHSA feed | No | `false` |
| `use-osv` | Use built-in OSV feed | No | `false` |
| `source` | Vulnerability source URL or path (single source) | No* | - |
| `sources` | Multiple vulnerability sources (one per line) | No* | - |
| `source-format` | Format of the source (`json` or `csv`) | No | Auto-detected |
| `csv-columns` | CSV column mapping | No | `name,versions` |
| `working-directory` | Directory to scan | No | `.` |
| `fail-on-vulnerabilities` | Fail workflow if vulnerabilities found | No | `true` |
| `script-version` | Version/branch of script to use | No | `main` |
| `additional-args` | Extra arguments for the script | No | - |
| `only-package-json` | Scan only package.json files (skip lockfiles) | No | `false` |
| `only-lockfiles` | Scan only lockfiles (skip package.json files) | No | `false` |
| `lockfile-types` | Comma-separated list of lockfile types to scan | No | - |

\* At least one source must be provided (`use-ghsa`, `use-osv`, `source`, or `sources`).

**Note on `lockfile-types`:** Available types are `npm`, `yarn`, `pnpm`, `bun`, `deno`.

#### Advanced Examples

**Check with both built-in feeds (GHSA and OSV):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      use-osv: true
```

**Check with built-in GHSA and custom source:**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      source: 'https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl'
```

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

**Multiple sources (custom remote sources):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      sources: |
        https://example.com/vulns1.json
        https://example.com/vulns2.purl
        https://example.com/vulns3.csv
```

**Multiple sources (local files):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      sources: |
        ./data/custom-vulns.json
        ./data/company-advisories.purl
```

**Multiple sources (built-in feeds + custom sources):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      use-osv: true
      sources: |
        ./data/custom-vulns.json
        https://example.com/company-advisories.purl
```

**Scan only package.json files (skip lockfiles):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      only-package-json: true
```

**Scan only lockfiles (skip package.json files):**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      only-lockfiles: true
```

**Scan only specific lockfile types:**

```yaml
jobs:
  check-yarn:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      lockfile-types: 'yarn'
```

**Scan only npm and yarn lockfiles:**

```yaml
jobs:
  check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      only-lockfiles: true
      lockfile-types: 'npm,yarn'
```

#### Using Local Source Files

You can commit vulnerability feeds directly to your repository and use them as local sources. This is useful for:

- Custom vulnerability databases specific to your organization
- Offline/air-gapped environments
- Faster CI runs (no network fetch required)

**Example workflow structure:**

```text
your-repo/
├── .github/
│   └── workflows/
│       └── security-check.yml
├── security/
│   ├── vulnerabilities.json
│   └── custom-advisories.purl
└── package.json
```

**Complete workflow example:**

```yaml
name: Security Check with Local Sources

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  vulnerability-check:
    uses: maxgfr/package-checker.sh/.github/workflows/reusable-check.yml@main
    with:
      use-ghsa: true
      use-osv: true
      sources: |
        ./security/custom-advisories.purl
      fail-on-vulnerabilities: true
```

This approach combines the built-in GHSA and OSV feeds with your organization's custom vulnerability database stored in the repository.

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
            --default-source-ghsa
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
          ../package-checker/script.sh --default-source-ghsa

      - name: Or use custom source
        working-directory: project
        run: |
          curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl
```

To use a private vulnerability source or to increase GitHub API rate limits, supply a token:

```yaml
- name: Check with private source
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash -s -- --source https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/ghsa.purl
```

## GitLab CI

### Using Docker Image (Recommended)

Example using the official Docker image with built-in feeds:

```yaml
vulnerability-check:
  image: ghcr.io/maxgfr/package-checker.sh:latest
  script:
    - package-checker --default-source-ghsa

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
    - cd /tmp/checker && ./script.sh --default-source-ghsa
```

## Tips for CI

- **Use Docker images for simplicity**: The official Docker images include built-in vulnerability feeds, making setup easier
  - Full image: `ghcr.io/maxgfr/package-checker.sh:latest` (~43MB with GHSA and OSV feeds)
  - Lightweight: `ghcr.io/maxgfr/package-checker.sh:lite` (~27MB, bring your own data)
- **Use built-in feeds for zero-setup scanning**: The `data/ghsa.purl` and `data/osv.purl` feeds are automatically updated and ready to use
- Store secrets (GitHub tokens, private URLs) in the CI provider's secret store and reference them as environment variables
- If you only want to fetch packages from GitHub (without scanning), use `--github-only` and `--github-output` to save files for later inspection
- For reproducible results, pin the Docker image to a specific tag or pin the `script.sh` URL to a commit SHA instead of `refs/heads/main`
