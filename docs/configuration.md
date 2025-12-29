# Configuration

`package-checker` can read options from a JSON config file so you do not have to repeat long command‑line arguments.

The convention in this repository is to use a file named `.package-checker.config.json` at the project root.

## Basic example

```json
{
  "sources": [
    { "source": "https://example.com/vulns.json", "name": "Internal DB" },
    { "source": "https://example.com/vulns.csv", "format": "csv", "columns": "name,versions" }
  ],
  "github": {
    "org": "my-org",
    "token": "",
    "output": "./packages"
  },
  "options": {
    "ignore_paths": ["node_modules", ".yarn", ".git"],
    "dependency_types": ["dependencies", "devDependencies"]
  }
}
```

**Note:** By default, package-checker uses the built-in GHSA feed automatically. For built-in feeds, use `--default-source-ghsa` (default), `--default-source-osv`, or `--default-source-ghsa-osv` instead of specifying paths in the config file.

This configuration corresponds to:

```bash
package-checker \
  --source "https://example.com/vulns.json" \
  --source "https://example.com/vulns.csv" --format csv --csv-columns "name,versions"
```

### Using Default Sources

package-checker automatically uses the GHSA feed by default. You can explicitly specify sources:

```bash
# Use default GHSA source (automatic if no source specified)
package-checker

# Use both GHSA and OSV sources for comprehensive coverage
package-checker --default-source-ghsa-osv

# Use only OSV source instead of default GHSA
package-checker --default-source-osv

# Combine with custom sources
package-checker --default-source-ghsa-osv --source "https://example.com/vulns.json"
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

- `source` (string) — URL or file path to vulnerability database
- `name` (optional, string) — human‑readable label used in logs
- `format` (optional, string) — `"json"`, `"csv"`, `"purl"`, `"sarif"`, `"sbom-cyclonedx"`, or `"trivy-json"`; auto‑detected if omitted
- `columns` (optional, string) — for CSV, column mapping such as `"name,versions"`

**Note:** For built-in vulnerability feeds (GHSA and OSV), use the command-line flags `--default-source-ghsa`, `--default-source-osv`, or `--default-source-ghsa-osv` instead of adding them to the configuration file. This ensures automatic path detection across different environments (Homebrew, Docker, local clone).

See [Data formats](./data-formats.md) for format details.

### `github`

GitHub settings:

- `org` (optional) — default organization name
- `token` (optional) — GitHub personal access token (PAT)
- `output` (optional) — directory where fetched `package.json` files are saved

These values can be overridden by command‑line flags (`--github-org`, `--github-token`, `--github-output`).

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
