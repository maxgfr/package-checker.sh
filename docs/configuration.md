# Configuration

`package-checker` can read options from a JSON config file so you do not have to repeat long command‑line arguments.

The convention in this repository is to use a file named `.package-checker.config.json` at the project root.

## Basic example

```json
{
  "sources": [
    { "source": "data/ghsa.purl", "format": "purl", "name": "GHSA Feed" },
    { "source": "https://example.com/vulns.json", "name": "Internal DB" },
    { "source": "https://example.com/vulns.csv", "format": "csv", "columns": "name,versions" }
  ],
  "github": {
    "org": "my-org",
    "repo": "owner/repo",
    "token": "",
    "output": "./packages"
  },
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git"],
    "dependency_types": ["dependencies", "devDependencies"]
  }
}
```

**Note:** The configuration above combines the built-in GHSA feed (from `data/ghsa.purl`) with custom external sources.

This configuration roughly corresponds to:

```bash
package-checker \
  --source "data/ghsa.purl" \
  --source "https://example.com/vulns.json" \
  --source "https://example.com/vulns.csv" --format csv --csv-columns "name,versions"
```

### Using Default Sources (Recommended)

Instead of manually specifying paths to built-in feeds, you can use the auto-detection feature:

```bash
# Use both GHSA and OSV default sources (auto-detected)
package-checker --default-source

# Use only GHSA default source
package-checker --default-source-ghsa

# Use only OSV default source
package-checker --default-source-osv

# Combine with custom sources
package-checker --default-source --source "https://example.com/vulns.json"
```

The `--default-source*` options automatically find vulnerability feeds in this order:

1. Homebrew installation: `$(brew --prefix)/share/package-checker/data/`
2. Local directory: `./data/`
3. Docker container: `/app/data/`
4. Remote GitHub: `https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/`

This makes it easy to use the built-in feeds across different environments without hardcoding paths.

…plus the GitHub defaults and ignore options when you use GitHub‑related flags.

## Top‑level structure

The config file has three main sections:

- `sources`: where vulnerability data comes from  
- `github`: how to fetch `package.json` files from GitHub  
- `options`: how the local scan behaves

### `sources`

Each entry in `sources` describes one vulnerability data source:

- `url` (string) — URL to remote vulnerability database
- `file` (string) — Local file path (e.g., `"data/ghsa.purl"` for built-in feeds)
- `name` (optional, string) — human‑readable label used in logs
- `format` (optional, string) — `"json"`, `"csv"`, `"purl"`, `"sarif"`, `"sbom-cyclonedx"`, or `"trivy-json"`; auto‑detected if omitted
- `columns` (optional, string) — for CSV, column mapping such as `"name,versions"`

**Note:** Use either `url` or `file`, not both. The built-in vulnerability feeds are in the `data/` folder:
- `data/ghsa.purl` — GitHub Security Advisory database (~5,000+ npm vulnerabilities)
- `data/osv.purl` — Open Source Vulnerabilities database (~206,000+ npm vulnerabilities)

See [Data formats](./data-formats.md) for format details.

### `github`

GitHub settings used when you pass `--github-org` or `--github-repo`:

- `org` (optional) — default organization name.  
- `repo` (optional) — default `owner/repo` string.  
- `token` (optional) — GitHub personal access token (PAT).  
- `output` (optional) — directory where fetched `package.json` files are saved.

These values can be overridden by command‑line flags (`--github-org`, `--github-repo`, `--github-token`, `--github-output`).

### `options`

General scan behaviour:

- `ignore_paths` — list of directory or file patterns to skip (for example `node_modules`, `.yarn`, `.git`).
- `dependency_types` — which dependency sections to check in `package.json`, e.g. `["dependencies", "devDependencies"]`.

## File Type Filtering

By default, package-checker scans **both** lockfiles and package.json files. You can control what gets scanned using command-line flags:

### Scan only package.json files

```bash
package-checker --only-package-json
```

This will skip all lockfile scanning and only analyze package.json files.

### Scan only lockfiles

```bash
package-checker --only-lockfiles
```

This will skip package.json scanning and only analyze lockfiles.

### Filter specific lockfile types

```bash
# Only scan yarn.lock files
package-checker --lockfile-types yarn

# Only scan npm and yarn lockfiles
package-checker --lockfile-types npm,yarn

# Combine with --only-lockfiles for explicit filtering
package-checker --only-lockfiles --lockfile-types yarn
```

Available lockfile types:

- `npm` — package-lock.json, npm-shrinkwrap.json
- `yarn` — yarn.lock (Classic & Berry/v2+)
- `pnpm` — pnpm-lock.yaml
- `bun` — bun.lock
- `deno` — deno.lock

**Note:** These options are only available as command-line flags and cannot be set in the configuration file.

## Interaction with command‑line flags

- If a config file is present and you **do not** pass `--no-config`, `script.sh` will load it.  
- Any command‑line flags take precedence over values from the config file.  
- Passing `--no-config` forces the script to ignore `.package-checker.config.json` completely.

