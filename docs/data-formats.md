# Data formats

package-checker.sh consumes one or more **vulnerability databases** that you provide.
Three formats are supported:

- **JSON** — flexible structure with named fields for exact versions and version ranges.
- **CSV** — simple table, typically with `package_name` and `package_versions` columns.
- **PURL** — Package URL format, a standardized way to identify software packages.

## JSON format

JSON sources are objects where keys are package names. Each package entry can contain:

- `package_versions`: list of **exact vulnerable versions**
- `package_versions_range`: list of **version range expressions**

Example:

```json
{
  "package-name": {
    "package_versions": ["1.0.0", "2.0.0"]
  },
  "lodash": {
    "package_versions_range": [">=4.0.0 <4.17.21"]
  }
}
```

You can mix `package_versions` and `package_versions_range` entries for the same package if needed.

## CSV format

CSV sources are usually two-column files with a header:

```csv
package_name,package_versions
express,4.16.0
lodash,">=4.0.0 <4.17.21"
```

- `package_name` — package to match in `dependencies` / lockfiles.
- `package_versions` — either a single version (e.g. `4.16.0`) or a range (e.g. `">=4.0.0 <4.17.21"`).

If your CSV uses a different layout, specify the columns explicitly:

```bash
./script.sh --source ./vulns.csv --format csv --csv-columns "package_name,package_versions"
```

## PURL format

PURL (Package URL) is a standardized format for identifying software packages. Each line contains a package URL in the format:

```text
pkg:type/namespace/name@version
```

Examples:

```text
pkg:npm/lodash@4.17.21
pkg:npm/express@4.16.0
pkg:npm/@babel/core@7.12.0
pkg:npm/react@>=16.0.0 <16.14.0
```

- `type` — package ecosystem (e.g., `npm`, `pypi`, `maven`)
- `namespace` — optional namespace or scope (e.g., `@babel`)
- `name` — package name
- `version` — exact version or version range

**Key features:**

- One package per line
- Supports exact versions: `pkg:npm/lodash@4.17.21`
- Supports version ranges: `pkg:npm/express@>=4.0.0 <4.17.0`
- Empty lines and lines starting with `#` are ignored (comments)
- The package name is extracted from the last component of the path

Example PURL file:

```purl
# Critical vulnerabilities
pkg:npm/lodash@4.17.20
pkg:npm/minimist@0.0.8

# Version ranges
pkg:npm/express@>=4.0.0 <4.17.21
pkg:npm/@babel/traverse@<7.23.2
```

To use a PURL file:

```bash
./script.sh --source ./vulns.purl --format purl
```

## Version ranges

Version ranges follow standard npm style (for example `1.2.3`, `>=4.0.0 <4.17.21`, `^16.0.0`).
When a range contains spaces, make sure it is quoted in CSV files so the shell and CSV parser treat it as a single field.
