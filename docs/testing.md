# Testing with the included fixtures

The repository includes a `test-fixtures/` directory containing:

- Small example projects using different package managers (npm, Yarn, pnpm, Bun, Deno, monorepo)
- Example vulnerability databases (`test-vulnerabilities.json` and `test-vulnerabilities.csv`)

This lets you test `script.sh` safely without touching your own projects.

## 1. Clone the repository

```bash
git clone https://github.com/maxgfr/package-checker.sh.git
cd package-checker.sh
```

## 2. Explore `test-fixtures/`

```bash
ls test-fixtures
# you'll see example JSON/CSV vulnerability files and small project folders
```

You can open the subdirectories to inspect the different lockfiles and `package.json` setups.

## 3. Run the script against the fixtures

From inside `test-fixtures/`:

```bash
cd test-fixtures
chmod +x ../script.sh

# JSON vulnerability database
../script.sh --source test-vulnerabilities.json
```

This will:

- Scan all example projects under `test-fixtures/`
- Use `test-vulnerabilities.json` as the vulnerability database
- Print a report of any vulnerable packages found

## 4. Try the CSV example

```bash
../script.sh --source test-vulnerabilities.csv --format csv --csv-columns "name,versions"
```

This uses the same projects but a CSV vulnerability file instead of JSON.

## 5. Target specific fixtures

You can focus on a particular test project by changing directory before running the script:

```bash
cd npm-project
../script.sh --source ../test-vulnerabilities.json
```

You can repeat this for the other subfolders like `yarn-project`, `pnpm-project`, `bun-project`, `deno-project`, etc.

## 6. Use fixtures to test configuration

The `test-fixtures/` directory also contains a sample config file:

- `.package-checker.config.json`  
- Example vulnerability JSON/CSV files

From `test-fixtures/` you can run:

```bash
../script.sh --config .package-checker.config.json
```

This is useful to verify how configuration, ignore patterns and multiple sources behave before applying them to real repositories.

For more details on options and formats, see:

- [Data formats](./data-formats.md)
- [Configuration](./configuration.md)
