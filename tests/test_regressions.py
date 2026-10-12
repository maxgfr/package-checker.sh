"""Offline CLI regressions. Python is a test dependency only."""
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("CHECKER_SCRIPT", ROOT / "script.sh")).resolve()
BASH = os.environ.get("TEST_BASH", "bash")


class CheckerCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="checker-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def scan(self, *args, code=1):
        result = subprocess.run(
            [BASH, str(SCRIPT), *map(str, args)], cwd=self.root,
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def project(self, version="1.5.0", name="package.json"):
        self.write(name, json.dumps({"dependencies": {"demo": version}}))

    def feed(self, *lines):
        return self.write("feed.purl", "\n".join(lines) + "\n")


class CheckerTests(CheckerCase):
    def test_same_range_preserves_distinct_advisories(self):
        self.project()
        feed = self.feed(
            "pkg:npm/demo@>=1.0.0 <2.0.0?ghsa=GHSA-first&severity=high",
            "pkg:npm/demo@>=1.0.0 <2.0.0?ghsa=GHSA-second&severity=low",
        )
        output = self.scan("--source", feed)
        self.assertIn("GHSA-first", output)
        self.assertIn("GHSA-second", output)

    def test_same_exact_version_across_sources(self):
        self.project()
        first = self.feed("pkg:npm/demo@1.5.0?ghsa=GHSA-first&severity=high")
        second = self.write("second.purl", "pkg:npm/demo@1.5.0?ghsa=GHSA-second&severity=low\n")
        output = self.scan("--source", first, "--source", second)
        self.assertIn("GHSA-first", output)
        self.assertIn("GHSA-second", output)

    def test_duplicate_advisory_is_reported_once(self):
        self.project()
        feed = self.feed("pkg:npm/demo@>=1.0.0 <2.0.0?ghsa=GHSA-first&severity=high")
        output = self.scan("--source", feed, "--source", feed)
        self.assertEqual(output.count("GHSA: GHSA-first"), 1)

    def test_cve_only_advisories_are_preserved(self):
        self.project()
        feed = self.feed(
            "pkg:npm/demo@1.5.0?cve=CVE-2026-1111",
            "pkg:npm/demo@1.5.0?cve=CVE-2026-2222",
        )
        output = self.scan("--source", feed)
        self.assertIn("CVE-2026-1111", output)
        self.assertIn("CVE-2026-2222", output)

    def test_exports_round_trip_special_characters(self):
        name = 'directory "quoted" \\ slash/package.json'
        self.project(name=name)
        feed = self.feed('pkg:npm/demo@1.5.0?source=custom"quoted\\source')
        self.scan("--source", feed, "--export-json", "out.json", "--export-csv", "out.csv")
        report = json.loads((self.root / "out.json").read_text())
        row = report["vulnerabilities"][0]
        self.assertEqual(row["file"], "./" + name)
        self.assertEqual(row["source"], 'custom"quoted\\source')
        csv_row = next(csv.DictReader(io.StringIO((self.root / "out.csv").read_text())))
        self.assertEqual(csv_row["file"], row["file"])
        self.assertEqual(csv_row["source"], row["source"])

    def test_disjoint_intervals_are_not_overwritten_by_later_source(self):
        self.project("3.5.0")
        first = self.feed("pkg:npm/demo@>=3.0.0 <4.0.0?ghsa=GHSA-shared")
        second = self.write("second.purl", "pkg:npm/demo@>=1.0.0 <2.0.0?ghsa=GHSA-shared\n")
        self.assertIn("GHSA-shared", self.scan("--source", first, "--source", second))

    def test_inclusive_upper_bound_is_vulnerable(self):
        self.project("2.0.0")
        feed = self.feed("pkg:npm/demo@>=1.0.0 <=2.0.0?ghsa=GHSA-inclusive")
        self.assertIn("GHSA-inclusive", self.scan("--source", feed))

    def test_build_metadata_does_not_change_ordering(self):
        self.project("2.0.0+build.123")
        feed = self.feed("pkg:npm/demo@>=1.0.0 <2.0.0")
        self.scan("--source", feed, code=0)

    def test_numeric_prerelease_ordering(self):
        self.project("1.0.0-rc.10")
        feed = self.feed("pkg:npm/demo@>=1.0.0-rc.2 <1.0.0")
        self.assertIn("demo@1.0.0-rc.10", self.scan("--source", feed))

    def test_or_ranges(self):
        feed = self.feed("pkg:npm/demo@>=1.0.0 <2.0.0 || >=3.0.0 <4.0.0?ghsa=GHSA-or")
        for version, code in [("1.5.0", 1), ("2.5.0", 0), ("3.5.0", 1), ("4.0.0", 0)]:
            with self.subTest(version=version):
                self.project(version)
                self.scan("--source", feed, code=code)

    def test_missing_argument_has_diagnostic(self):
        for option in ["--source", "--config", "--package-name", "--package-version", "--ecosystems"]:
            with self.subTest(option=option):
                output = self.scan(option)
                self.assertIn("requires", output)

    def test_optional_export_filename(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0")
        self.scan("--source", feed, "--export-json")
        self.assertEqual(json.loads((self.root / "vulnerabilities.json").read_text())["summary"]["total_occurrences"], 1)

    def test_source_merge_preserves_literal_dollar_text(self):
        self.project()
        first = self.feed("pkg:npm/demo@1.5.0?source=$LITERAL_VALUE")
        second = self.write("second.purl", "pkg:npm/demo@1.5.0?source=two\n")
        self.scan("--source", first, "--source", second, "--export-json", "out.json")
        self.assertEqual(json.loads((self.root / "out.json").read_text())["vulnerabilities"][0]["source"], "$LITERAL_VALUE")

    def test_config_ignore_paths_applies_before_discovery(self):
        self.project(name="ignored/package.json")
        feed = self.feed("pkg:npm/demo@1.5.0")
        config = self.write("config.json", json.dumps({"sources": [{"source": str(feed)}], "options": {"ignore_paths": ["ignored"]}}))
        self.scan("--config", config, code=0)

    def test_config_source_failure_is_not_a_clean_scan(self):
        self.project()
        config = self.write("config.json", json.dumps({"sources": [{"source": "missing.purl"}]}))
        self.assertIn("not found", self.scan("--config", config))

    def test_missing_explicit_config_is_an_error(self):
        self.assertIn("not found", self.scan("--config", "missing.json"))

    def test_malformed_json_is_an_error(self):
        self.project()
        feed = self.write("bad.json", '{"demo":{"versions":["1.5.0"]}')
        self.assertIn("Invalid JSON", self.scan("--source", feed))

    def test_all_source_formats(self):
        fixtures = ROOT / "test-fixtures"
        for extension in ["json", "csv", "purl", "sarif", "sbom.cdx.json", "trivy.json"]:
            with self.subTest(format=extension):
                output = self.scan(fixtures / "npm-project", "--source", fixtures / ("test-vulnerabilities." + extension))
                self.assertIn("next@16.0.3", output)

    def test_csv_semver_ranges(self):
        self.project()
        for version_range in ["^1.0.0", "~1.5.0", "*", ">=1.0.0 <2.0.0 || >=3.0.0 <4.0.0"]:
            with self.subTest(version_range=version_range):
                feed = self.write("feed.csv", 'name,versions\ndemo,"' + version_range + '"\n')
                self.assertIn("demo@1.5.0", self.scan("--source", feed))

    def test_export_write_failure_is_not_reported_as_success(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0")
        for option in ["--export-json", "--export-csv"]:
            output = self.scan("--source", feed, option, "missing/report")
            self.assertNotIn("report exported", output)


def compare(function, left, right):
    """Run one sourced comparator and return its COMPARE_RESULT."""
    result = subprocess.run([BASH, "-c", 'source "$1"; "$2" "$3" "$4"; printf %s "$COMPARE_RESULT"',
                             "bash", str(SCRIPT), function, left, right],
                            text=True, capture_output=True, timeout=10)
    return result.stdout


class VersionRegressionTests(CheckerCase):
    def test_go_pseudo_version_matches_open_lower_bound(self):
        self.write("go.mod", "module example.com/app\n\nrequire example.com/demo v0.0.0-20210101120000-abcdef123456\n")
        feed = self.feed("pkg:golang/example.com/demo@>=0 <0.0.0-20220315000000-ffffffffffff")
        self.assertIn("demo@0.0.0-20210101120000-abcdef123456", self.scan("--source", feed))

    def test_npm_zero_prerelease_matches_open_lower_bound(self):
        self.project("0.0.0-experimental-1")
        self.scan("--source", self.feed("pkg:npm/demo@>=0"))

    def test_composer_glued_rc_and_patch_releases(self):
        lock = {"packages": [{"name": "vendor/demo", "version": "VERSION"}]}
        for version, constraint, code in [("9.4.7", "<9.4.0RC1", 0), ("9.4.0-beta2", "<9.4.0RC1", 1),
                                          ("2.4.7", "<2.4.7-p4", 1), ("2.4.7-p5", "<2.4.7-p4", 0),
                                          ("v1.0.0-beta10", ">=1.0.0-beta9 <1.0.0", 1)]:
            with self.subTest(version=version, constraint=constraint):
                self.write("composer.lock", json.dumps(lock).replace("VERSION", version))
                self.scan("--source", self.feed("pkg:composer/vendor/demo@" + constraint), code=code)

    def test_semver_compares_every_numeric_part_and_strips_v(self):
        self.assertEqual(compare("compare_versions", "1.0.0.1", "1.0.0"), "1")
        self.assertEqual(compare("compare_versions", "v1.0.0", "2.0.0"), "-1")

    def test_prerelease_order_is_locale_independent(self):
        env = dict(os.environ, LC_ALL="fr_FR.UTF-8", LANG="fr_FR.UTF-8")
        result = subprocess.run([BASH, "-c", 'source "$1"; compare_versions 5.0.0-beta1 5.0.0-RC1; printf %s "$COMPARE_RESULT"',
                                 "bash", str(SCRIPT)], text=True, capture_output=True, timeout=10, env=env)
        self.assertEqual(result.stdout, "1")

    def test_gem_trailing_zero_segments(self):
        self.assertEqual(compare("compare_versions_gem", "1.0.0.pre.1", "1.0.pre.1"), "0")

    def test_custom_range_dialects(self):
        for version_range, version, code in [(">=1.0,<2.0", "2.5.0", 0), (">=1.0,<2.0", "1.5.0", 1),
                                             (">= 1.0 < 2.0", "1.5.0", 1), ("==1.5.0", "1.5.0", 1),
                                             ("=1.5.0", "1.5.1", 0), ("^1", "1.5.0", 1), ("^1", "2.0.0", 0),
                                             ("~1.5", "1.5.9", 1), ("~1.5", "1.6.0", 0)]:
            with self.subTest(version_range=version_range, version=version):
                self.project(version)
                feed = self.write("feed.csv", 'name,versions\ndemo,"' + version_range + '"\n')
                self.scan("--source", feed, code=code)

    def test_unknown_range_token_warns(self):
        self.project()
        result = subprocess.run([BASH, str(SCRIPT), "--source", str(self.feed("pkg:npm/demo@>=1.0.0 <2.0.0 foo"))],
                                cwd=self.root, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn("unsupported version range", result.stderr)

    def test_floating_action_tags_are_not_compared(self):
        self.write(".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v46\n"
                   "      - uses: tj-actions/changed-files@v45.0.0\n")
        output = self.scan("--source", self.feed("pkg:githubactions/tj-actions/changed-files@<46.0.1"))
        self.assertIn("changed-files@45.0.0", output)
        self.assertNotIn("changed-files@46", output)

if __name__ == "__main__":
    unittest.main(verbosity=2)
