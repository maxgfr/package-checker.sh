"""Feature matrix and adversarial boundaries, independent of real feed updates."""
import json
import os
import shutil
import subprocess
import unittest

from test_regressions import BASH, ROOT, SCRIPT, CheckerCase


class FeatureTests(CheckerCase):
    def test_each_registered_file_in_isolation(self):
        fixtures = ROOT / "test-fixtures"
        rows = [
            ("npm-project/package-lock.json", "package-lock.json", "next@16.0.3", "npm"),
            ("npm-shrinkwrap-project/npm-shrinkwrap.json", "npm-shrinkwrap.json", "next@16.0.3", "npm"),
            ("yarn-project/yarn.lock", "yarn.lock", "next@16.0.3", "npm"),
            ("yarn-berry-project/yarn.lock", "yarn.lock", "react-server-dom-webpack@19.0.0", "npm"),
            ("pnpm-project/pnpm-lock.yaml", "pnpm-lock.yaml", "next@16.0.3", "npm"),
            ("bun-project/bun.lock", "bun.lock", "next@16.0.3", "npm"),
            ("deno-project/deno.lock", "deno.lock", "next@16.0.3", "npm"),
            ("rust-project/Cargo.lock", "Cargo.lock", "time@0.1.45", "cargo"),
            ("go-project/go.sum", "go.sum", "golang.org/x/text@0.3.5", "golang"),
            ("go-project/go.mod", "go.mod", "golang.org/x/text@0.3.5", "golang"),
            ("python-project/requirements.txt", "requirements.txt", "django@3.2", "pypi"),
            ("poetry-project/poetry.lock", "poetry.lock", "pillow@8.0.0", "pypi"),
            ("poetry-project/poetry.lock", "uv.lock", "pillow@8.0.0", "pypi"),
            ("poetry-project/poetry.lock", "pdm.lock", "pillow@8.0.0", "pypi"),
            ("pipenv-project/Pipfile.lock", "Pipfile.lock", "django-rest-framework@3.0.0", "pypi"),
            ("ruby-project/Gemfile.lock", "Gemfile.lock", "rack@2.2.3", "gem"),
            ("php-project/composer.lock", "composer.lock", "guzzlehttp/guzzle@7.4.0", "composer"),
            ("maven-project/gradle.lockfile", "gradle.lockfile", "org.apache.logging.log4j:log4j-core@2.14.1", "maven"),
            ("maven-project/pom.xml", "pom.xml", "org.apache.commons:commons-lang3@3.14.0", "maven"),
            ("nuget-project/packages.lock.json", "packages.lock.json", "newtonsoft.json@12.0.2", "nuget"),
            ("dart-project/pubspec.lock", "pubspec.lock", "dio@4.0.6", "pub"),
            ("elixir-project/mix.lock", "mix.lock", "sweet_xml@0.6.6", "hex"),
            ("swift-project/Package.resolved", "Package.resolved", "github.com/apple/swift-nio@2.10.0", "swift"),
            ("actions-project/.github/workflows/ci.yml", ".github/workflows/ci.yaml", "tj-actions/changed-files@35", "githubactions"),
        ]
        for index, (source, target, expected, ecosystem) in enumerate(rows):
            with self.subTest(file=source, target=target):
                path = self.root / str(index) / target
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(fixtures / source, path)
                feed = fixtures / ("test-vulnerabilities.json" if ecosystem == "npm" else "test-vulnerabilities-multi.purl")
                if target == "pom.xml":
                    feed = self.feed("pkg:maven/org.apache.commons/commons-lang3@3.14.0")
                self.scan(self.root / str(index), "--source", feed, "--export-json", "out.json")
                findings = json.loads((self.root / "out.json").read_text())["vulnerabilities"]
                self.assertEqual({(row["package"], row["ecosystem"]) for row in findings}, {(expected, ecosystem)})

    def test_filter_only_manifest_and_only_lockfile(self):
        fixtures = ROOT / "test-fixtures"
        for flag, filename in [("--only-package-json", "package.json"), ("--only-lockfiles", "package-lock.json")]:
            with self.subTest(flag=flag):
                self.scan(fixtures / "npm-project", "--source", fixtures / "test-vulnerabilities.json", flag, "--export-json", "out.json")
                rows = json.loads((self.root / "out.json").read_text())["vulnerabilities"]
                self.assertTrue(rows)
                self.assertTrue(all(row["file"].endswith("/" + filename) for row in rows))

    def test_detect_then_load_and_override(self):
        self.write("requirements.txt", "Django==3.2\n")
        self.write("empty.purl", "# intentionally empty fixture\n")
        for flags, expected in [("", ["ghsa-pypi.purl"]), ("--ecosystems rust --default-source-ghsa-osv", ["ghsa-cargo.purl", "osv-cargo.purl"])]:
            with self.subTest(flags=flags):
                result = subprocess.run([BASH, "-c", '''source "$1"
                    find_default_source() { printf '%s\\n' "$1" >> requested; printf '%s/empty.purl' "$PWD"; }
                    shift
                    main "$@"
                    ''', "test", str(SCRIPT), *flags.split()], cwd=self.root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((self.root / "requested").read_text().splitlines(), expected)
                (self.root / "requested").unlink()

    def test_config_with_no_sources_uses_default_feed(self):
        self.write(".package-checker.config.json", '{"sources":[],"options":{"ecosystems":["rust"]}}')
        self.write("empty.purl", "# empty\n")
        result = subprocess.run([BASH, "-c", '''source "$1"
            find_default_source() { printf '%s\\n' "$1" >> requested; printf '%s/empty.purl' "$PWD"; }
            main
            ''', "test", str(SCRIPT)], cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "requested").read_text().splitlines(), ["ghsa-cargo.purl"])

    def test_git_ignored_files_are_skipped(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        self.project(name="ignored/package.json")
        self.write(".gitignore", "ignored/\n")
        self.scan("--source", self.feed("pkg:npm/demo@1.5.0"), code=0)

    def test_custom_dependency_types(self):
        self.write("package.json", json.dumps({"dependencies": {"demo": "1.5.0"}, "devDependencies": {"demo-dev": "1.5.0"}, "peerDependencies": {"demo-peer": "1.5.0"}}))
        feed = self.feed("pkg:npm/demo@1.5.0", "pkg:npm/demo-dev@1.5.0", "pkg:npm/demo-peer@1.5.0")
        config = self.write("config.json", json.dumps({"sources": [{"source": str(feed)}], "options": {"dependency_types": ["dependencies"]}}))
        self.scan("--config", config, "--export-json", "out.json")
        rows = json.loads((self.root / "out.json").read_text())["vulnerabilities"]
        self.assertEqual([row["package"] for row in rows], ["demo@1.5.0"])

    def test_package_lookup_preserves_project_search_contract(self):
        self.project()
        self.assertIn("demo@1.5.0", self.scan("--package-name", "demo"))
        self.scan("--package-name", "demo", "--package-version", "2.0.0", code=0)

    def test_csv_custom_columns_and_crlf(self):
        self.project()
        source = self.write("feed.csv", 'ignored,package,affected\r\nvalue,demo,">=1.0.0 <2.0.0"\r\n')
        for columns in ["package,affected", "2,3"]:
            self.assertIn("demo@1.5.0", self.scan("--source", source, "--csv-columns", columns))

    def test_invalid_flags_are_errors(self):
        for args in [("--unknown",), ("--only-lockfiles", "--only-package-json"), ("--only-package-json", "--lockfile-types", "npm"), ("--ecosystem", "invalid")]:
            with self.subTest(args=args):
                self.scan(*args)

    def test_help_and_version(self):
        for args in [("--help",), ("--version",), ("--help", "format"), ("--help-ai",)]:
            self.assertTrue(self.scan(*args, code=0).strip())

    def test_piped_install_entrypoint(self):
        result = subprocess.run([BASH, "-s", "--", "--help"], input=SCRIPT.read_text(), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--source", result.stdout)

    def test_sourcing_does_not_run_main(self):
        result = subprocess.run([BASH, "-c", 'source "$1"; printf loaded', "test", str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "loaded")

    def test_scan_needs_no_json_runtime_dependency(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        # Deliberately omit jq, Python and Node from the scanner environment.
        for tool in ["bash", "awk", "curl", "find", "git", "sort", "sed", "tr", "wc", "grep", "dirname", "basename", "realpath", "mktemp", "rm", "seq", "xargs", "tail", "head", "cat"]:
            path = shutil.which(tool)
            if path:
                (bin_dir / tool).symlink_to(path)
        result = subprocess.run([str(bin_dir / "bash"), str(SCRIPT), "--source", str(feed)], cwd=self.root, env={**os.environ, "PATH": str(bin_dir)}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("demo@1.5.0 (vulnerable)", result.stdout)
        self.assertNotIn("command not found", result.stderr)

    def test_json_validator_against_standard_parser(self):
        inputs = ['{}', '[]', '{"a":[true,false,null,-1.5e+3]}', '{"s":"quote\\\"and\\\\slash\\u00e9"}', '{"a":1,}', '[1,]', '{"a" 1}', '{"a":01}', '{"a":"\\x"}', '{"a":"unterminated}', '{"a":1} trailing', '', '{"a":"literal\nnewline"}']
        for value in inputs:
            with self.subTest(value=value):
                try:
                    json.loads(value)
                    expected = 0
                except ValueError:
                    expected = 1
                result = subprocess.run([BASH, "-c", 'source "$1"; json_is_valid "$2"', "test", str(SCRIPT), value], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected)

    def test_export_controls_and_empty_count(self):
        self.scan("--help", code=0)
        result = subprocess.run([BASH, "-c", '''source "$1"
            export_vulnerabilities_json empty.json >/dev/null
            VULNERABLE_PACKAGES=('package.json|npm|demo@1.0.0')
            VULN_METADATA_SOURCE[npm:demo@1.0.0]=$'tab\\tline\\ncontrol\\001'
            export_vulnerabilities_json controls.json >/dev/null
            ''', "test", str(SCRIPT)], cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.root / "empty.json").read_text())["summary"], {"total_unique_vulnerabilities": 0, "total_occurrences": 0})
        self.assertEqual(json.loads((self.root / "controls.json").read_text())["vulnerabilities"][0]["source"], "tab\tline\ncontrol\x01")


if __name__ == "__main__":
    unittest.main(verbosity=2)
