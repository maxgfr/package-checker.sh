# Data formats

package-checker.sh consumes one or more **vulnerability databases** that you provide.  
Two formats are supported:

- **JSON** — flexible structure with named fields for exact versions and version ranges.
- **CSV** — simple table, typically with `package_name` and `package_versions` columns.

## JSON format

JSON sources are objects where keys are package names. Each package entry can contain:

- `vulnerability_version`: list of **exact vulnerable versions**
- `vulnerability_version_range`: list of **version range expressions**

Example:

```json
{
  "package-name": {
    "vulnerability_version": ["1.0.0", "2.0.0"]
  },
  "lodash": {
    "vulnerability_version_range": [">=4.0.0 <4.17.21"]
  }
}
```

You can mix `vulnerability_version` and `vulnerability_version_range` entries for the same package if needed.

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

## Version ranges

Version ranges follow standard npm style (for example `1.2.3`, `>=4.0.0 <4.17.21`, `^16.0.0`).  
When a range contains spaces, make sure it is quoted in CSV files so the shell and CSV parser treat it as a single field.
