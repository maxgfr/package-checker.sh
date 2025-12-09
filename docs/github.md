# GitHub integration

package-checker.sh can fetch `package.json` files from GitHub organizations or single repositories, then run the vulnerability check against them.

## Requirements

- Network access to `api.github.com`
- (Recommended) A GitHub personal access token (PAT) for higher rate limits and private repositories

You can pass the token explicitly with `--github-token` or via the `GITHUB_TOKEN` environment variable.

## Scan a GitHub organization

Scan all repositories in an organization and immediately check them against your vulnerability database:

```bash
GITHUB_TOKEN="$GITHUB_TOKEN" ./script.sh \
  --github-org my-org \
  --source ./my-vulns.json
```

Or, passing the token as a flag:

```bash
./script.sh \
  --github-org my-org \
  --github-token "$GITHUB_TOKEN" \
  --source ./my-vulns.json
```

## Scan a single repository

```bash
./script.sh \
  --github-repo owner/repo \
  --github-token "$GITHUB_TOKEN" \
  --source ./my-vulns.json
```

For public repositories you may omit the token, but requests will be rate limited by GitHub.

## Fetch only (no analysis)

Sometimes you only want to download `package.json` files and inspect them locally or run several tools on them.

```bash
./script.sh \
  --github-org my-org \
  --github-only \
  --github-output ./my-packages
```

This will:

- List repositories in `my-org`
- Fetch their `package.json` files
- Write them under `./my-packages`
- Skip the vulnerability scan step

## Using configuration files

You can put default GitHub settings in `.package-checker.config.json`:

```json
{
  "github": {
    "org": "my-org",
    "token": "",
    "output": "./packages"
  }
}
```

Then run:

```bash
./script.sh --config .package-checker.config.json --source ./my-vulns.json
```

Command-line flags still override config values. See [Configuration](./configuration.md) for more details.
