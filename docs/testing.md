# Testing with the included fixtures

## Complete offline suite

From the repository root, run:

```bash
bash build.sh
bash tests/run.sh
```

The scanner requires Bash 4+ and its existing shell utilities. Tests additionally
require Python 3, jq and ShellCheck; they do not install project dependencies or
contact GitHub. HTTP cases use a localhost server and GitHub operations use mocks.
No real issues are created. Python, Node and jq are deliberately absent from one
scan test to enforce the runtime dependency boundary.

`tests/test-fixtures.sh` contains the original CI scenarios, including the existing
version and bug regression suites. The Python suites add isolated tests for every
registered lockfile name, source formats, CLI/configuration, exports, GitHub,
feed generation and failure handling. uv/pdm dispatch uses synthetic fixtures with
the shared TOML package structure; this is not a claim to support every historical
lockfile format revision.

CI runs the suite on macOS (system awk and gawk) and Linux (gawk and mawk), verifies
that the generated script matches its sources, and tests lite, npm-only and
all-ecosystem Docker images. These jobs execute after the changes are pushed.
With a running local Docker engine, `bash tests/test-docker.sh` builds and checks
the same three image variants without publishing them.

## Reproducible performance comparison

Keep the previous distributable outside the checkout, then run:

```bash
python3 tests/benchmark.py /path/to/previous/script.sh ./script.sh
```

Each of five offline scenarios has one warmup and five measured runs: small npm,
polyglot, a 5,432-line feed, a generated 100-package monorepo and a 5,000-dependency
npm lockfile. The benchmark
alternates old/new execution order and reports median elapsed time, paired speedup,
peak resident memory and canonical JSON report hashes.
It also prints changed report rows, so a faster run cannot silently hide lost
findings. Run it without concurrent tests/builds to reduce timing noise.

See [the verification report](verification.md) for the changes, measurements and
remaining validation limits from the September 2026 review.

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
../../script.sh --source ../test-vulnerabilities.json
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
