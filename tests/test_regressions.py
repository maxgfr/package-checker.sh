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


if __name__ == "__main__":
    unittest.main(verbosity=2)
