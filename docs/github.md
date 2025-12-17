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

## Create GitHub issues automatically

You can automatically create GitHub issues for repositories with vulnerabilities. Two modes are available:

### Multiple issues (one per package)

Use `--create-multiple-issues` to create **one issue per vulnerable package**:

```bash
./script.sh \
  --github-org my-org \
  --github-token "$GITHUB_TOKEN" \
  --source ./my-vulns.json \
  --create-multiple-issues
```

### Single consolidated issue

Use `--create-single-issue` to create **one issue containing all vulnerabilities**:

```bash
./script.sh \
  --github-repo owner/repo \
  --github-token "$GITHUB_TOKEN" \
  --source ./my-vulns.json \
  --create-single-issue
```

### Comparison

| Flag | Issues Created | Best For |
|------|----------------|----------|
| `--create-multiple-issues` | One per vulnerable package | Tracking individual package updates |
| `--create-single-issue` | One consolidated report | Overview of all security issues |

### Issue content

Both modes include:

- Severity levels with visual indicators (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- Links to GHSA advisories and CVE details
- Affected files and versions
- Recommendations for remediation
- Automatic labeling with `security`, `vulnerability` and `dependencies` tags

**Note:** Both flags require a GitHub token with `repo` scope to create issues.

## Direct package lookup with GitHub scanning

You can combine direct package lookup with GitHub organization scanning to find where a specific package is used:

```bash
# Find all repositories using a specific package version
./script.sh \
  --github-org my-org \
  --github-token "$GITHUB_TOKEN" \
  --package-name next \
  --package-version 16.0.3

# Find all repositories using any version of a package
./script.sh \
  --github-org my-org \
  --github-token "$GITHUB_TOKEN" \
  --package-name lodash

# Find repositories with packages in a version range
./script.sh \
  --github-org my-org \
  --github-token "$GITHUB_TOKEN" \
  --package-name express \
  --package-version '^4.17.0'
```

This is useful for:

- Incident response: "Which repos use the vulnerable version?"
- Upgrade planning: "Where do we need to update this package?"
- Dependency auditing: "Is anyone still using this deprecated package?"
