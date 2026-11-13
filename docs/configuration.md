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

1. `--data-dir DIR`, or the `PACKAGE_CHECKER_DATA_DIR` environment variable
2. The `data/` directory next to the script, symlinks resolved (a git checkout, a release, the Homebrew and Docker `package-checker` links)
3. Homebrew installation: `$(brew --prefix)/share/package-checker/data/`
4. Docker container: `/app/data/`
5. The download cache: `PACKAGE_CHECKER_CACHE_DIR`, default `${XDG_CACHE_HOME:-~/.cache}/package-checker/feeds`
6. Remote GitHub: `https://raw.githubusercontent.com/maxgfr/package-checker.sh/refs/heads/main/data/`
7. Local directory: `./data/`, only when none of the above is reachable (an offline piped run), with a warning. The scanned project is usually the current directory, so its own `data/` never replaces the built-in feeds while those can be reached.

The first local copy (1 to 5) younger than `--max-feed-age` days (default 2, or the `PACKAGE_CHECKER_MAX_FEED_AGE` environment variable; `0` = no limit) wins. The full Docker image sets `PACKAGE_CHECKER_MAX_FEED_AGE=0`: its baked-in feeds are those of the image build and are not downloaded again (see [Docker](docker.md)). The age of a feed comes from its first line, `# generated: <UTC date>` (written when the feed is built), or from the file modification time when it has none. When no copy is fresh, the published feed is downloaded once and kept for the next runs, with a `# fetched: <UTC date>` line that keeps it fresh for `--max-feed-age` days: in `--data-dir` when it is given and writable, else in the download cache. When that download fails, the newest local copy is used with a warning (`"stale": true` in the JSON report). A connection failure or timeout is remembered for the rest of the run: the other feeds use their local copies without trying GitHub again, and the connect timeout is 5 seconds when a local copy exists. An explicit `--data-dir` that does not exist is an error (exit 2); a feed missing from it, or older than `--max-feed-age`, is said on stderr before another copy is used. `package-checker --update-feeds --data-dir DIR [--ecosystems npm,pypi]` downloads the current feeds into `DIR` (each file replaced atomically, the previous copy kept when a download fails or is not a purl feed, such as an HTML page) and exits: 0 when every feed was updated, 3 when some could not be, 2 when `DIR` cannot be written.

The JSON report lists every feed in `sources` (origin, entry count, date, age, `stale`). A requested feed that cannot be found or loaded makes the scan incomplete: it is said on stderr, `incomplete` is `true` in the JSON report, and the exit code is 3 instead of 0 (`--strict`: also instead of 1, and the run stops before the scan).

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

- `ignore_paths` — directories to skip; they are not even descended into (default: `node_modules`, `.yarn`, `.git`, `vendor`).
- `dependency_types` — which dependency sections to check in `package.json`, e.g. `["dependencies", "devDependencies"]`.
- `ecosystems` — optional list that overrides which ecosystems' built-in feeds are loaded, instead of auto-detecting them from the project's lockfiles. Accepts lockfile-type aliases (`npm`, `yarn`, `pnpm`, `bun`, `deno`, `python`, `go`, `rust`, `ruby`, `php`, `maven`, `nuget`, `dart`, `hex`, `swift`, `actions`) or purl types (`npm`, `pypi`, `golang`, `cargo`, …), e.g. `["npm"]`. An empty list (or one with only empty strings) keeps the default. The `--ecosystems` command-line flag takes precedence when both are set.
- `runtime_check` — set to `false` to skip the Node.js / PHP runtime version check (default: `true`, see [Runtime versions](../README.md#runtime-versions-nodejs--php)). The `--no-runtime-check` flag does the same from the command line.

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
- `bun` — bun.lock, bun.lockb (read through `bun` when installed)
- `deno` — deno.lock
- `python` — requirements.txt (and its `requirements-*.txt`, `requirements_*.txt`, `*-requirements.txt`, `requirements/*.txt`, `constraints.txt` variants), poetry.lock, uv.lock, pdm.lock, Pipfile.lock
- `go` — go.sum, go.mod (only without a go.sum beside it)
- `rust` — Cargo.lock
- `ruby` — Gemfile.lock
- `php` — composer.lock
- `maven` — gradle.lockfile, `*-gradle.lockfile`, pom.xml
- `nuget` — packages.lock.json
- `dart` — pubspec.lock
- `hex` — mix.lock
- `swift` — Package.resolved
- `actions` — GitHub Actions workflows (`.github/workflows/*.yml`, `*.yaml`)

**Note:** These options are only available as command-line flags and cannot be set in the configuration file.

### Git-ignored files

When the scanned directory is inside a git repository, the lockfiles and manifests it ignores are scanned too: a library often ignores its lockfile, yet the file on disk is what was installed. The scan prints how many it scanned (`files.gitignored_scanned` in the JSON report). Pass `--exclude-gitignored` to skip and list them instead (`files.gitignored_skipped`). `--include-gitignored` is still accepted and changes nothing.

### Pruned directories

Besides `ignore_paths`, discovery skips the trees that hold caches, package stores and build outputs rather than projects, so a scan of a home directory does not walk them: `~/Library` (only when the home directory is the scanned one or below it; its `Mobile Documents` (iCloud Drive) and `CloudStorage` (Dropbox, Google Drive, OneDrive...) folders are scanned), `.Trash`, `.cache`, `.npm`, `.pnpm-store`, `.yarn/cache`, `.cargo/registry`, `.rustup`, `.gradle`, `.m2`, `site-packages`, `__pycache__`, `.next`, `.nuxt`, `Pods` and `DerivedData`. The skipped directories are listed (`ℹ️  Skipping N cache, package-store or build directory(ies)`, and `files.pruned` in the JSON report). Pass `--no-default-prune` to descend into them.

## Interaction with command‑line flags

- If a config file is present and you **do not** pass `--no-config`, `script.sh` will load it.
- Its `options` and `github` settings always apply, also when sources are given on the command line (`-s`, `--default-source-*`, `--package-name`).
- Its `sources` are used only when the command line gives no source: command-line sources take precedence.
- Any command‑line flags take precedence over values from the config file.
- Passing `--no-config` ignores `.package-checker.config.json`; a file passed explicitly with `-c/--config` is always read.
