# Configuration

`script.sh` can read options from a JSON config file so you do not have to repeat long command‑line arguments.

The convention in this repository is to use a file named `.package-checker.config.json` at the project root.

## Basic example

```json
{
  "sources": [
    { "url": "https://example.com/vulns.json", "name": "Internal DB" },
    { "url": "https://example.com/vulns.csv", "format": "csv", "columns": "package_name,package_versions" }
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

This configuration roughly corresponds to:

```bash
./script.sh \
  --source "https://example.com/vulns.json" \
  --source "https://example.com/vulns.csv" --format csv --csv-columns "package_name,package_versions"
```

…plus the GitHub defaults and ignore options when you use GitHub‑related flags.

## Top‑level structure

The config file has three main sections:

- `sources`: where vulnerability data comes from  
- `github`: how to fetch `package.json` files from GitHub  
- `options`: how the local scan behaves

### `sources`

Each entry in `sources` describes one vulnerability data source:

- `url` (string) — URL or file path to the JSON / CSV database.  
- `name` (optional, string) — human‑readable label used in logs.  
- `format` (optional, string) — `"json"` or `"csv"`; auto‑detected if omitted.  
- `columns` (optional, string) — for CSV, column mapping such as `"package_name,package_versions"`.

See [Data formats](./data-formats.md) for JSON / CSV schema details.

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

## Interaction with command‑line flags

- If a config file is present and you **do not** pass `--no-config`, `script.sh` will load it.  
- Any command‑line flags take precedence over values from the config file.  
- Passing `--no-config` forces the script to ignore `.package-checker.config.json` completely.

