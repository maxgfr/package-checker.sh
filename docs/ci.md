# Continuous Integration examples

This page contains simple CI snippets for running `package-checker.sh` in common CI systems.

## GitHub Actions

A minimal GitHub Actions job that runs the scanner on each push or pull request:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check for vulnerabilities
        run: |
          curl -sS https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/script.sh | bash
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
