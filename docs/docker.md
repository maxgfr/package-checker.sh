# Docker Usage

package-checker.sh provides two official Docker images for easy deployment and CI/CD integration.

**Command Reference:** When installed via Homebrew, the command is `package-checker`. Inside Docker containers, it's available as `package-checker`. When using the script directly, it's `./script.sh`.

## Available Images

| Variant | Image | Built-in feeds | Best for |
|---|---|---|---|
| Full (default) | `ghcr.io/maxgfr/package-checker.sh:latest` | all 12 ecosystems (`ghsa.purl`/`osv.purl` for npm + `ghsa-*`/`osv-*`) | any repo, polyglot included, scanned fully offline |
| Full — `-all` alias | `ghcr.io/maxgfr/package-checker.sh-all:latest` | identical to the default full image | users already pinned to the `-all` name |
| Lite | `ghcr.io/maxgfr/package-checker.sh-lite:latest` | none (bring your own) | smallest image; custom/self-hosted feeds |

The default full image bakes in the GHSA/OSV feeds for **every** supported ecosystem (npm, pypi, golang, maven, cargo, gem, composer, nuget, pub, hex, swift, githubactions) plus the runtime feed (`osv-runtime.purl`). The `-all` image used to be the only one shipping every ecosystem; it is still published, identical to the default, so existing pins keep working.

### Full Image (Recommended)

**Image:** `ghcr.io/maxgfr/package-checker.sh:latest`
**Size:** ~75MB
**Includes:** Script + GHSA and OSV vulnerability feeds for all supported ecosystems (~39MB of data)

This image includes pre-downloaded vulnerability feeds for every ecosystem, so you can start scanning immediately — even offline or air-gapped — without fetching external data.

### Lightweight Image

**Image:** `ghcr.io/maxgfr/package-checker.sh-lite:latest`
**Size:** ~27MB
**Includes:** Script only (bring your own vulnerability data)

Use this image when you want to provide your own vulnerability sources or fetch feeds on demand.

### Which ecosystems does an image ship?

Feeds are selected at build time via the `FEED_ECOSYSTEMS` build-arg (default `all`):

```bash
# Default: every ecosystem's feeds (same as the published :latest)
docker build -t package-checker .

# npm feeds only (slimmer image)
docker build --build-arg FEED_ECOSYSTEMS=npm -t package-checker-npm .

# A custom subset (comma-separated purl types; npm keeps its legacy filenames)
docker build --build-arg FEED_ECOSYSTEMS=npm,pypi,golang -t package-checker-jsy .
```

Baking every feed into the image does not make scans heavier: package-checker still uses detect-then-load, so a scan only reads the feeds of the ecosystems it detects in your project. To force a fixed set regardless of what is detected, pass `--ecosystems npm,pypi` (or set `ecosystems` in the config file).

**Runtime fallback (subset builds):** an image built without a given ecosystem's feed is not stuck. When scanning detects, say, a `requirements.txt`, package-checker auto-downloads the missing `osv-pypi.purl` / `ghsa-pypi.purl` from raw GitHub, as long as it has network access.

This keeps the repository's [separation guarantee](vulnerability-feeds.md#-separation-guarantee-per-ecosystem-feeds-never-combined): feeds are per-ecosystem files, never a single combined bundle.

### Homebrew tap note

The Homebrew formula installs `script.sh` together with **every** `data/*.purl` feed into `$(brew --prefix)/share/package-checker/data/`, so a `brew`-installed `package-checker` also covers all ecosystems offline, just like the default Docker image.

## Quick Start

### Using the Full Image

Scan your project with the default GHSA feed:

```bash
# Scan current directory with default GHSA feed (automatic)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest

# Scan with both GHSA and OSV feeds for comprehensive coverage
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest --default-source-ghsa-osv
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

### Scan Specific Directory

```bash
# Scan a subdirectory (uses default GHSA automatically)
docker run -v $(pwd):/workspace ghcr.io/maxgfr/package-checker.sh:latest \
  /workspace/my-project

# Scan with both GHSA and OSV feeds
docker run -v /absolute/path:/workspace ghcr.io/maxgfr/package-checker.sh:latest \
  /workspace \
  --default-source-ghsa-osv
```

### Check Specific Package

```bash
# Uses default GHSA source automatically
docker run ghcr.io/maxgfr/package-checker.sh:latest \
  --package-name express \
  --package-version 4.17.1
```

### Scan GitHub Organization

```bash
# Uses default GHSA source automatically
docker run \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/maxgfr/package-checker.sh:latest \
  --github-org myorg \
  --github-token $GITHUB_TOKEN
```

### Export Results

```bash
# Uses default GHSA source automatically
docker run \
  -v $(pwd):/workspace \
  ghcr.io/maxgfr/package-checker.sh:latest \
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
            ghcr.io/maxgfr/package-checker.sh:latest
```

### GitLab CI

```yaml
vulnerability-check:
  image: ghcr.io/maxgfr/package-checker.sh:latest
  script:
    - package-checker
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
      - run: package-checker
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
  ghcr.io/maxgfr/package-checker.sh:latest
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

The images are based on `alpine:3.22` and include:

- `bash` — Shell interpreter
- `curl` — For HTTP requests and GitHub API
- `gawk` — AWK implementation for fast JSON parsing
- `script.sh` — The package-checker script
- `data/` (full images only) — GHSA and OSV vulnerability feeds for the ecosystems selected by the `FEED_ECOSYSTEMS` build-arg (default `all`)

## Updates

The Docker images are automatically rebuilt and published via GitHub Actions when:

- Changes are pushed to the main branch
- A new release is published
- The workflow is manually triggered

The vulnerability feeds in the full image are automatically updated every 12 hours.

---

**Questions?** Open an issue on [GitHub](https://github.com/maxgfr/package-checker.sh/issues).
