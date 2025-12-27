# Docker Usage

package-checker.sh provides two official Docker images for easy deployment and CI/CD integration.

**Command Reference:** When installed via Homebrew, the command is `package-checker`. Inside Docker containers, it's available as `package-checker`. When using the script directly, it's `./script.sh`.

## Available Images

### Full Image (Recommended)

**Image:** `ghcr.io/maxgfr/package-checker.sh:latest`
**Size:** ~43MB
**Includes:** Script + GHSA and OSV vulnerability feeds (~15MB of data)

This image includes pre-downloaded vulnerability feeds, so you can start scanning immediately without fetching external data.

### Lightweight Image

**Image:** `ghcr.io/maxgfr/package-checker.sh:lite`
**Size:** ~27MB
**Includes:** Script only (bring your own vulnerability data)

Use this image when you want to provide your own vulnerability sources or fetch feeds on demand.

## Quick Start

### Using the Full Image

Scan your project with built-in GHSA feed:

```bash
# Scan current directory with GHSA feed (recommended)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa

# Scan with both GHSA and OSV feeds
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source
```

### Using the Lightweight Image

Provide your own vulnerability source:

```bash
# Use remote vulnerability source
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:lite \
  --source https://your-domain.com/vulnerabilities.json

# Mount local vulnerability file
docker run \
  -v $(pwd):/workspace \
  -v $(pwd)/my-vulns.json:/app/vulns.json \
  ghcr.io/maxgfr/package-checker.sh:lite \
  --source /app/vulns.json
```

## Common Usage Patterns

### Check Specific Package

```bash
docker run ghcr.io/maxgfr/package-checker.sh:latest \
  --default-source-ghsa \
  --package-name express \
  --package-version 4.17.1
```

### Scan GitHub Organization

```bash
docker run \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --default-source-ghsa \
  --github-org myorg \
  --github-token $GITHUB_TOKEN
```

### Export Results

```bash
docker run \
  -v $(pwd):/workspace \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --default-source-ghsa \
  --export-json results.json \
  --export-csv results.csv
```

### Use Configuration File

```bash
# Create config file
cat > .package-checker.config.json <<EOF
{
  "sources": [
    {"source": "data/ghsa.purl", "format": "purl"},
    {"source": "https://example.com/custom.json", "format": "json"}
  ]
}
EOF

# Run with config
docker run \
  -v $(pwd):/workspace \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --config /workspace/.package-checker.config.json
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for vulnerabilities
        run: |
          docker run -v ${{ github.workspace }}:/workspace \
            ghcr.io/maxgfr/package-checker.sh:latest \
            --default-source-ghsa
```

### GitLab CI

```yaml
vulnerability-check:
  image: ghcr.io/maxgfr/package-checker.sh:latest
  script:
    - package-checker --default-source-ghsa
```

### CircleCI

```yaml
version: 2.1
jobs:
  vulnerability-check:
    docker:
      - image: ghcr.io/maxgfr/package-checker.sh:latest
    steps:
      - checkout
      - run: package-checker --default-source-ghsa
```

## Building Images Locally

If you want to build the images yourself:

### Build Full Image

```bash
docker build -t package-checker:full -f Dockerfile .
```

### Build Lightweight Image

```bash
docker build -t package-checker:lite -f Dockerfile.lite .
```

## Image Tags

- `latest` — Latest stable release from main branch (full image)
- `lite` — Latest stable release from main branch (lightweight image)
- `vX.Y.Z` — Specific version tag (if released)
- `main` — Latest commit from main branch (bleeding edge)

## Volume Mounts

The Docker images expect your project to be mounted at `/workspace`:

```bash
docker run -v /path/to/project:/workspace ghcr.io/maxgfr/package-checker.sh:latest [OPTIONS]
```

## Environment Variables

- `GITHUB_TOKEN` — GitHub personal access token for API requests and private repositories

```bash
docker run \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -v $(pwd):/workspace \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --github-org myorg
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with mounted volumes:

```bash
# Run with your user ID
docker run --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --default-source-ghsa
```

### Accessing Help

```bash
docker run ghcr.io/maxgfr/package-checker.sh:latest --help
```

### Debugging

Run the container interactively:

```bash
docker run -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  ghcr.io/maxgfr/package-checker.sh:latest
```

## Image Details

The images are based on `alpine:3.19` and include:

- `bash` — Shell interpreter
- `curl` — For HTTP requests and GitHub API
- `gawk` — AWK implementation for fast JSON parsing
- `script.sh` — The package-checker script
- `data/` (full image only) — GHSA and OSV vulnerability feeds

## Updates

The Docker images are automatically rebuilt and published via GitHub Actions when:

- Changes are pushed to the main branch
- A new release is published
- The workflow is manually triggered

The vulnerability feeds in the full image are automatically updated every 12 hours.

---

**Questions?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).
