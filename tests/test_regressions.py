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
                output = self.scan(option, code=2)
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
        self.assertIn("not found", self.scan("--config", config, code=2))

    def test_missing_explicit_config_is_an_error(self):
        self.assertIn("not found", self.scan("--config", "missing.json", code=2))

    def test_malformed_json_is_an_error(self):
        self.project()
        feed = self.write("bad.json", '{"demo":{"versions":["1.5.0"]}')
        self.assertIn("Invalid JSON", self.scan("--source", feed, code=2))

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
            output = self.scan("--source", feed, option, "missing/report", code=2)
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


class ParserRegressionTests(CheckerCase):
    def sarif(self, *packages):
        results = [{"ruleId": "GHSA-%04d" % i, "message": {"text": "Package: %s\nInstalled Version: %s\nSeverity: HIGH" % pkg}}
                   for i, pkg in enumerate(packages)]
        return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": results}]}

    def test_sarif_reads_every_result_with_scoped_names(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "1.0.1", "@scope/b": "2.0.0", "c": "3.0.0"}}))
        report = self.write("r.sarif", json.dumps(self.sarif(("a", "1.0.10"), ("a", "1.0.1"), ("@scope/b", "2.0.0"), ("c", "3.0.0"))))
        output = self.scan("--source", report)
        for found in ["a@1.0.1", "@scope/b@2.0.0", "c@3.0.0"]:
            self.assertIn(found, output)

    def test_minified_sbom_and_trivy_reports(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "1.0.0", "b": "2.0.0"}}))
        sbom = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "ref-b", "purl": "pkg:npm/b@2.0.0"}],
                "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "pkg:npm/a@1.0.0"}]},
                                    {"id": "CVE-2", "affects": [{"ref": "ref-b"}]}]}
        output = self.scan("--source", self.write("r.cdx.json", json.dumps(sbom, separators=(",", ":"))))
        self.assertIn("a@1.0.0", output)
        self.assertIn("b@2.0.0", output)
        trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1.0.0"},
                                                  {"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "2.0.0"}]}]}
        output = self.scan("--source", self.write("r.trivy.json", json.dumps(trivy, separators=(",", ":"))))
        self.assertIn("a@1.0.0", output)
        self.assertIn("b@2.0.0", output)

    def test_two_json_sources_keep_every_version_and_metadata(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "1.0.0", "b": "2.0.0"}}))
        first = self.write("one.json", json.dumps({"a": {"versions": ["0.9.0", "1.0.0"], "ghsa": "GHSA-meta-data-json"}}))
        second = self.write("two.json", json.dumps({"a": {"versions": ["5.0.0"]}, "b": {"versions_range": [">=2.0.0 <3.0.0"]}}))
        output = self.scan("--source", first, "--source", second)
        self.assertIn("a@1.0.0", output)
        self.assertIn("b@2.0.0", output)
        self.assertIn("GHSA-meta-data-json", output)

    def test_headerless_csv_keeps_first_row(self):
        self.project()
        self.assertIn("demo@1.5.0", self.scan("--source", self.write("feed.csv", "demo,1.5.0\n")))

    def test_nuget_central_transitive(self):
        self.write("packages.lock.json", json.dumps({"version": 2, "dependencies": {"net8.0": {
            "Demo.Lib": {"type": "CentralTransitive", "requested": "[1.0.0, )", "resolved": "1.0.0"}}}}))
        self.assertIn("demo.lib@1.0.0", self.scan("--source", self.feed("pkg:nuget/Demo.Lib@1.0.0")))

    def test_deno_underscore_names(self):
        self.write("deno.lock", json.dumps({"version": "4", "npm": {"string_decoder@1.3.0_peer@2.0.0": {"integrity": "x"}}}, indent=2))
        self.assertIn("string_decoder@1.3.0", self.scan("--source", self.feed("pkg:npm/string_decoder@1.3.0")))

    def test_yarn_alias_and_crlf(self):
        classic = '"alias@npm:real@^1.0.0":\r\n  version "1.2.3"\r\n  resolved "x"\r\n'
        berry = '__metadata:\n  version: 6\n\n"alias@npm:real@^1.0.0":\n  version: 1.2.3\n  resolution: "real@npm:1.2.3"\n'
        for content in [classic, berry]:
            with self.subTest(content=content[:20]):
                self.write("yarn.lock", content)
                self.assertIn("real@1.2.3", self.scan("--source", self.feed("pkg:npm/real@1.2.3")))

    def test_bun_workspace_specs_are_not_versions(self):
        self.write("bun.lock", '{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": {\n      "dependencies": {\n'
                   '        "ms": "2",\n      },\n    },\n  },\n  "packages": {\n'
                   '    "ms": ["ms@2.1.3", "", {}, "sha512-x"],\n  }\n}\n')
        output = self.scan("--source", self.feed("pkg:npm/ms@<2.1.0"), code=0)
        self.assertNotIn("ms@2 ", output)

    def test_pnpm_scoped_name_starting_with_digit(self):
        self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  '@scope/3d-lib@1.0.0':\n    resolution: {integrity: x}\n")
        self.assertIn("@scope/3d-lib@1.0.0", self.scan("--source", self.feed("pkg:npm/%40scope/3d-lib@1.0.0")))

    def test_tarball_dependencies_use_their_recorded_version(self):
        feed = self.feed("pkg:npm/xlsx@<0.20.2?ghsa=GHSA-xlsx")
        lockfiles = {
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\npackages:\n\n"
                              "  xlsx@https://cdn.sheetjs.com/xlsx-0.19.3/xlsx-0.19.3.tgz:\n"
                              "    resolution: {tarball: https://cdn.sheetjs.com/xlsx-0.19.3/xlsx-0.19.3.tgz}\n"
                              "    version: 0.19.3\n    engines: {node: '>=0.8'}\n",
            "yarn.lock": '"xlsx@https://cdn.sheetjs.com/xlsx-0.19.3/xlsx-0.19.3.tgz":\n  version "0.19.3"\n',
            "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/xlsx": {
                "version": "0.19.3", "resolved": "https://cdn.sheetjs.com/xlsx-0.19.3/xlsx-0.19.3.tgz"}}}),
            "bun.lock": '{\n  "lockfileVersion": 1,\n  "packages": {\n'
                        '    "xlsx": ["xlsx@https://cdn.sheetjs.com/xlsx-0.19.3/xlsx-0.19.3.tgz", '
                        '{ "bin": { "xlsx": "./bin/xlsx.njs" } }, "sha512-x"],\n  }\n}\n',
        }
        for name, content in lockfiles.items():
            with self.subTest(lockfile=name):
                path = self.write(name, content)
                self.assertIn("xlsx@0.19.3", self.scan("--source", feed))
                path.unlink()

    def test_split_requirements_files_and_wildcard_pins(self):
        feed = self.feed("pkg:pypi/django@3.2", "pkg:pypi/flask@>=0")
        self.write("requirements-dev.txt", "Django==3.2\n")
        self.write("requirements/base.txt", "flask==1.0.*\n")
        output = self.scan("--source", feed)
        self.assertIn("django@3.2", output)
        self.assertNotIn("flask", output.split("SUMMARY")[1])

    def test_uv_lock_skips_local_project(self):
        self.write("uv.lock", 'version = 1\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = { editable = "." }\n\n'
                   '[[package]]\nname = "requests"\nversion = "2.0.0"\nsource = { registry = "https://pypi.org/simple" }\n')
        output = self.scan("--source", self.feed("pkg:pypi/demo@1.0.0", "pkg:pypi/requests@2.0.0"))
        self.assertIn("requests@2.0.0", output)
        self.assertNotIn("demo@1.0.0", output)

    def test_pom_comments_multiline_properties_and_ranges(self):
        self.write("pom.xml", """<project><properties><lib.version>2.0.0</lib.version></properties><dependencies>
<!-- <dependency><groupId>g</groupId><artifactId>commented</artifactId><version>1.0.0</version></dependency> -->
<dependency><groupId>g</groupId><artifactId>multi</artifactId><version>
  1.0.0
</version></dependency>
<dependency><groupId>g</groupId><artifactId>prop</artifactId><version>${lib.version}</version></dependency>
<dependency><groupId>g</groupId><artifactId>range</artifactId><version>[1.0,2.0)</version></dependency>
</dependencies></project>""")
        feed = self.feed("pkg:maven/g/commented@1.0.0", "pkg:maven/g/multi@1.0.0", "pkg:maven/g/prop@2.0.0", "pkg:maven/g/range@>=0")
        summary = self.scan("--source", feed).split("SUMMARY")[1]
        self.assertIn("g:multi@1.0.0", summary)
        self.assertIn("g:prop@2.0.0", summary)
        self.assertNotIn("commented", summary)
        self.assertNotIn("g:range", summary)

    def test_swift_ssh_urls_and_trailing_slash(self):
        pins = [{"identity": "a", "location": "git@github.com:Owner/Repo-A.git", "state": {"version": "1.0.0"}},
                {"identity": "b", "location": "https://github.com/owner/repo-b/", "state": {"version": "1.0.0"}}]
        self.write("Package.resolved", json.dumps({"pins": pins, "version": 2}, indent=2))
        output = self.scan("--source", self.feed("pkg:swift/github.com/owner/repo-a@1.0.0", "pkg:swift/github.com/owner/repo-b@1.0.0"))
        self.assertIn("github.com/owner/repo-a@1.0.0", output)
        self.assertIn("github.com/owner/repo-b@1.0.0", output)

    def test_package_json_null_section_and_non_semver_specs(self):
        self.write("package.json", json.dumps({"dependencies": None, "scripts": {"demo": "1.5.0"},
                                               "devDependencies": {"a": "git+https://x/a.git", "b": "github:o/b",
                                                                   "c": "catalog:", "d": "latest", "e": "patch:e@1.0.0"}}))
        feed = self.feed("pkg:npm/demo@1.5.0", *["pkg:npm/%s@>=0" % n for n in "abcde"])
        self.scan("--source", feed, code=0)

class ScanRegressionTests(CheckerCase):
    def test_package_json_covered_by_lockfile_is_skipped(self):
        self.write("package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "^4.17.0"}}, "node_modules/lodash": {"version": "4.18.1"}}}))
        output = self.scan("--source", self.feed("pkg:npm/lodash@<4.17.21"), code=0)
        self.assertIn("covered by a lockfile", output)

    def test_workspace_member_covered_by_root_lockfile(self):
        self.write("package.json", json.dumps({"workspaces": ["packages/*"]}))
        self.write("yarn.lock", '"lodash@^4.17.0":\n  version "4.18.1"\n')
        self.write("packages/app/package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
        self.scan("--source", self.feed("pkg:npm/lodash@<4.17.21"), code=0)

    def test_package_json_without_lockfile_uses_declared_versions(self):
        self.write("sub/package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
        output = self.scan("--source", self.feed("pkg:npm/lodash@<4.17.21"))
        self.assertIn("declared versions", output)

    def test_config_options_apply_with_command_line_sources(self):
        self.project(name="ignored/package.json")
        feed = self.feed("pkg:npm/demo@1.5.0")
        config = self.write("config.json", json.dumps({"options": {"ignore_paths": ["ignored"]}}))
        self.scan("-c", config, "--source", feed, code=0)
        self.write(".package-checker.config.json", json.dumps({"options": {"ignore_paths": ["ignored"]}}))
        self.scan("--source", feed, code=0)
        self.assertIn("demo@1.5.0", self.scan("--no-config", "--source", feed))

    def test_config_options_apply_with_default_source(self):
        self.project(name="ignored/package.json")
        self.write("empty.purl", "pkg:npm/demo@1.5.0\n")
        config = self.write("config.json", json.dumps({"options": {"ignore_paths": ["ignored"]}}))
        program = 'source "$1"; find_default_source() { printf "%s/empty.purl" "$PWD"; }; shift; main "$@"'
        result = subprocess.run([BASH, "-c", program, "test", str(SCRIPT), "-c", str(config), "--default-source-ghsa"],
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "root can read any directory")
    def test_unreadable_directory_does_not_abort(self):
        self.project()
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        result = subprocess.run([BASH, str(SCRIPT), "--source", str(self.feed("pkg:npm/demo@1.5.0"))],
                                cwd=self.root, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("could not be read", result.stderr)

    def test_gitignore_of_scanned_repository_applies(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        self.write("repo/.gitignore", "ignored/\n")
        self.project(name="repo/ignored/package.json")
        self.scan(repo, "--source", self.feed("pkg:npm/demo@1.5.0"), code=0)

    def test_gitignore_of_current_directory_does_not_apply(self):
        # A project cloned into a directory the current repository ignores.
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        self.write(".gitignore", "projects/\n")
        target = self.root / "projects" / "app"
        target.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        self.project(name="projects/app/package.json")
        self.assertIn("demo@1.5.0", self.scan(target, "--source", self.feed("pkg:npm/demo@1.5.0")))

    def test_utf8_bom_project_file(self):
        (self.root / "package.json").write_bytes(b"\xef\xbb\xbf" + json.dumps({"dependencies": {"demo": "1.5.0"}}).encode())
        self.assertIn("demo@1.5.0", self.scan("--source", self.feed("pkg:npm/demo@1.5.0")))

class CliRegressionTests(CheckerCase):
    def run_main(self, *args, prelude=""):
        program = 'source "$1"; ' + prelude + '; shift; main "$@"'
        return subprocess.run([BASH, "-c", program, "test", str(SCRIPT), *map(str, args)],
                              cwd=self.root, capture_output=True, text=True, timeout=30)

    def test_error_exit_codes(self):
        self.project()
        self.scan("--source", "missing.purl", code=2)
        self.scan("--source", self.feed("pkg:npm/demo@1.5.0"), "-f", "nonsense", code=2)
        self.scan("-f", "csv", code=2)

    def test_empty_default_feed_is_an_error(self):
        self.project()
        self.write("empty.purl", "# no entries\n")
        result = self.run_main("--default-source-ghsa", prelude='find_default_source() { printf "%s/empty.purl" "$PWD"; }')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("empty or unreadable", result.stdout)

    def test_unexpected_failure_exits_2(self):
        self.project()
        result = self.run_main("--source", self.feed("pkg:npm/demo@1.5.0"), prelude="discover_project_files() { false; }")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_bash_requirement_under_sh(self):
        result = subprocess.run(["sh", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=10)
        if "Usage:" in result.stdout:
            self.skipTest("sh is a modern bash here")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Bash 4", result.stderr)

    def test_format_and_columns_in_any_order(self):
        self.project()
        source = self.write("feed.txt", 'ignored,package,affected\nvalue,demo,">=1.0.0 <2.0.0"\n')
        for args in [("-f", "csv", "--csv-columns", "2,3"), ("--csv-columns", "2,3", "-f", "csv")]:
            with self.subTest(args=args):
                self.assertIn("demo@1.5.0", self.scan("--source", source, *args))

    def test_export_does_not_swallow_scan_path(self):
        self.project(name="app/package.json")
        output = self.scan("--source", self.feed("pkg:npm/demo@1.5.0"), "--export-json", "app")
        self.assertIn("demo@1.5.0", output)
        self.assertTrue((self.root / "vulnerabilities.json").is_file())

    def test_fetch_all_does_not_take_an_option_as_directory(self):
        result = self.run_main("--fetch-all", "--verbose",
                               prelude='check_dependencies() { :; }; fetch_all() { printf "%s" "$1" > called; }')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "called").read_text(), "data")

    def test_help_ai_failure_is_reported(self):
        result = self.run_main("--help-ai", "prompt", prelude="resolve_ai_doc() { return 1; }")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Could not load prompt.md", result.stdout)

    def test_package_lookup_checks_version_and_filters_project(self):
        self.write("package.json", json.dumps({"dependencies": {"demo": "1.5.0", "other": "1.0.0"}}))
        self.write("feed.purl", "pkg:npm/demo@>=2.0.0 <2.1.0?ghsa=GHSA-demo\npkg:npm/other@1.0.0?ghsa=GHSA-other\n")
        prelude = 'find_default_source() { printf "%s/feed.purl" "$PWD"; }'
        result = self.run_main("--package-name", "demo", "--package-version", "2.0.5", prelude=prelude)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[--package-name] demo@2.0.5", result.stdout)
        self.assertIn("GHSA-demo", result.stdout)
        self.assertNotIn("GHSA-other", result.stdout)
        result = self.run_main("--package-name", "demo", prelude=prelude)
        self.assertIn("demo@1.5.0", result.stdout)
        self.assertNotIn("other@1.0.0", result.stdout)

    def test_package_lookup_removes_its_temp_file(self):
        self.project()
        tmp = self.root / "tmp dir"
        tmp.mkdir()
        subprocess.run([BASH, str(SCRIPT), "--package-name", "demo", "--source", str(self.feed("pkg:npm/x@1.0.0"))],
                       cwd=self.root, env={**os.environ, "TMPDIR": str(tmp)}, capture_output=True, timeout=30)
        self.assertEqual(list(tmp.iterdir()), [])

    def test_issue_creation_requires_token_upfront(self):
        self.project()
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        result = subprocess.run([BASH, str(SCRIPT), "--create-single-issue", "--source", str(self.feed("pkg:npm/demo@1.5.0"))],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("require a GitHub token", result.stdout)

    def test_sbom_components_are_scanned_as_inventory(self):
        nested = {"purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0",
                  "components": [{"purl": "pkg:pypi/Requests@2.0.0"}]}
        sbom = self.write("target/bom.json", json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"purl": "pkg:maven/com.example/app@1.0.0"}},
            "components": [{"purl": "pkg:maven/org.springframework/spring-core@5.3.0", "components": [nested]}],
        }, indent=2))
        feed = self.feed("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0", "pkg:pypi/requests@2.0.0",
                         "pkg:maven/com.example/app@1.0.0")
        prelude = 'find_default_source() { printf "%s\\n" "$1" >> requested; return 1; }'
        result = self.run_main("--source", feed, "--default-source-ghsa", "--sbom", sbom, prelude=prelude)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        summary = result.stdout.split("SUMMARY")[1]
        self.assertIn("com.fasterxml.jackson.core:jackson-databind@2.9.0", summary)
        self.assertIn("requests@2.0.0", summary)
        self.assertNotIn("com.example:app", summary)
        self.assertEqual(set((self.root / "requested").read_text().split()), {"ghsa-maven.purl", "ghsa-pypi.purl"})

    def test_invalid_or_missing_sbom_is_an_error(self):
        self.assertIn("not found", self.scan("--sbom", "absent.json", code=2))
        self.scan("--sbom", code=2)
        bad = self.write("bom.json", '{"components": [')
        self.assertIn("Invalid JSON", self.scan("--source", self.feed("pkg:npm/demo@1.5.0"), "--sbom", bad, code=2))

    def test_pom_without_versions_points_to_sbom(self):
        self.write("pom.xml", """<project><dependencies>
<dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
<dependency><groupId>g</groupId><artifactId>parent-prop</artifactId><version>${parent.version}</version></dependency>
<dependency><groupId>g</groupId><artifactId>pinned</artifactId><version>1.0.0</version></dependency>
</dependencies></project>""")
        output = self.scan("--source", self.feed("pkg:maven/g/pinned@1.0.0"))
        self.assertIn("2 dependencies in ./pom.xml have no version here", output)
        self.assertIn("--sbom", output)

class ReachabilityRegressionTests(CheckerCase):
    FINDINGS = [
        {"config": {"scanner_name": "govulncheck"}},
        {"finding": {"osv": "GO-1", "trace": [{"module": "example.com/called", "version": "v1.0.0"}]}},
        {"finding": {"osv": "GO-1", "trace": [{"module": "example.com/called", "version": "v1.0.0",
                                               "package": "example.com/called", "function": "Parse"},
                                              {"module": "example.com/app", "function": "main"}]}},
        {"finding": {"osv": "GO-2", "trace": [{"module": "example.com/unused", "version": "v2.0.0",
                                               "package": "example.com/unused"}]}},
    ]

    def setUp(self):
        super().setUp()
        self.write("go.mod", "module example.com/app\n\nrequire (\n\texample.com/called v1.0.0\n\texample.com/unused v2.0.0\n)\n")
        self.feed("pkg:golang/example.com/called@1.0.0", "pkg:golang/example.com/unused@2.0.0")
        # Every PATH entry but those holding a real govulncheck.
        self.path = [d for d in os.environ["PATH"].split(os.pathsep) if not (Path(d) / "govulncheck").exists()]

    def run_scan(self, path):
        result = subprocess.run([BASH, str(SCRIPT), "--source", "feed.purl", "--go-reachability", "--export-json", "out.json"],
                                cwd=self.root, env={**os.environ, "PATH": os.pathsep.join(path)},
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        return result.stdout

    def test_go_reachability_annotates_findings(self):
        stream = "\n".join(json.dumps(m, indent=2) for m in self.FINDINGS)
        self.write("stream.json", stream + "\n")
        fake = self.write("bin/govulncheck", '#!/bin/sh\nprintf "%s\\n" "$*" > "$0.args"\ncat "' + str(self.root / "stream.json") + '"\n')
        fake.chmod(0o755)
        output = self.run_scan([str(fake.parent)] + self.path)
        summary = output.split("SUMMARY")[1]
        self.assertRegex(summary, r"example.com/called@1.0.0[^⚠]*Reachability: called \(govulncheck\)")
        self.assertRegex(summary, r"example.com/unused@2.0.0[^⚠]*Reachability: not called \(govulncheck\)")
        self.assertEqual((self.root / "bin/govulncheck.args").read_text().split(), ["-C", ".", "-format", "json", "./..."])
        rows = {row["package"]: row.get("reachability") for row in json.loads((self.root / "out.json").read_text())["vulnerabilities"]}
        self.assertEqual(rows, {"example.com/called@1.0.0": "called", "example.com/unused@2.0.0": "not called"})

    def test_go_reachability_without_govulncheck_warns(self):
        output = self.run_scan(self.path)
        self.assertIn("govulncheck not found", output)
        self.assertNotIn("Reachability:", output)
        rows = json.loads((self.root / "out.json").read_text())["vulnerabilities"]
        self.assertEqual(sorted(row["package"] for row in rows), ["example.com/called@1.0.0", "example.com/unused@2.0.0"])
        self.assertTrue(all("reachability" not in row for row in rows))

    def test_go_reachability_failure_warns(self):
        fake = self.write("bin/govulncheck", '#!/bin/sh\necho "go: missing go.sum entry" >&2\nexit 1\n')
        fake.chmod(0o755)
        output = self.run_scan([str(fake.parent)] + self.path)
        self.assertIn("govulncheck failed in . (exit 1): go: missing go.sum entry", output)
        self.assertNotIn("Reachability:", output)

    def test_go_reachability_failure_in_one_module_leaves_it_unannotated(self):
        (self.root / "go.mod").unlink()
        for module in ["a", "b"]:
            self.write(module + "/go.mod", "module example.com/" + module + "\n\nrequire example.com/unused v2.0.0\n")
        self.write("stream.json", json.dumps(self.FINDINGS[3], indent=2) + "\n")
        fake = self.write("bin/govulncheck", '#!/bin/sh\n[ "$2" = ./a ] || { echo "go: broken" >&2; exit 1; }\ncat "'
                          + str(self.root / "stream.json") + '"\n')
        fake.chmod(0o755)
        output = self.run_scan([str(fake.parent)] + self.path)
        self.assertIn("govulncheck failed in ./b (exit 1)", output)
        self.assertNotIn("Reachability:", output)
        rows = {row["file"]: row.get("reachability") for row in json.loads((self.root / "out.json").read_text())["vulnerabilities"]}
        self.assertEqual(rows, {"./a/go.mod": "not called", "./b/go.mod": None})


class ReportRegressionTests(CheckerCase):
    def shell(self, body):
        return subprocess.run([BASH, "-c", 'source "$1"; ' + body, "test", str(SCRIPT)],
                              cwd=self.root, text=True, capture_output=True, timeout=30)

    def test_ghsa_and_osv_records_of_one_advisory_merge(self):
        self.project()
        feed = self.feed("pkg:npm/demo@>=1.0.0 <1.6.0?ghsa=GHSA-same&cve=CVE-2026-1&severity=moderate&source=ghsa",
                         "pkg:npm/demo@>=1.0.0 <1.6.0?cve=CVE-2026-1&id=OSV-1&severity=high&source=osv")
        output = self.scan("--source", feed, "--export-json", "out.json")
        self.assertEqual(output.count("CVE: CVE-2026-1"), 1)
        self.assertIn("Source: ghsa, osv", output)
        row = json.loads((self.root / "out.json").read_text())["vulnerabilities"][0]
        self.assertEqual(row["severity"], "high")
        self.assertEqual(len(row["advisories"]), 1)
        self.assertEqual(row["advisories"][0]["id"], "OSV-1")
        self.assertEqual(row["advisories"][0]["ghsa"], "GHSA-same")

    def test_distinct_ghsa_ids_sharing_a_cve_stay_separate(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0?ghsa=GHSA-one&cve=CVE-2026-1", "pkg:npm/demo@1.5.0?ghsa=GHSA-two&cve=CVE-2026-1")
        output = self.scan("--source", feed)
        self.assertIn("GHSA-one", output)
        self.assertIn("GHSA-two", output)

    def test_exports_are_written_when_clean(self):
        self.project()
        (self.root / "out.json").write_text("stale")
        (self.root / "out.csv").write_text("stale")
        self.scan("--source", self.feed("pkg:npm/demo@9.9.9"), "--export-json", "out.json", "--export-csv", "out.csv", code=0)
        self.assertEqual(json.loads((self.root / "out.json").read_text())["vulnerabilities"], [])
        self.assertEqual((self.root / "out.csv").read_text().splitlines(),
                         ["package,file,severity,ghsa,cve,source,ecosystem,version,fix,reachability"])

    def test_export_fields_and_highest_fix(self):
        self.write("package.json", json.dumps({"dependencies": {"@scope/demo": "1.5.0"}}))
        feed = self.feed("pkg:npm/%40scope/demo@>=1.0.0 <1.6.0?ghsa=GHSA-low&severity=low",
                         "pkg:npm/%40scope/demo@>=1.0.0 <1.7.0?ghsa=GHSA-high&severity=critical")
        self.scan("--source", feed, "--export-json", "out.json", "--export-csv", "out.csv")
        row = json.loads((self.root / "out.json").read_text())["vulnerabilities"][0]
        self.assertEqual((row["name"], row["version"], row["fixed_in"], row["severity"], row["ghsa"]),
                         ("@scope/demo", "1.5.0", "1.7.0", "critical", "GHSA-high"))
        self.assertEqual({a["ghsa"] for a in row["advisories"]}, {"GHSA-low", "GHSA-high"})
        csv_row = next(csv.DictReader(io.StringIO((self.root / "out.csv").read_text())))
        self.assertEqual((csv_row["version"], csv_row["fix"]), ("1.5.0", "1.7.0"))
        self.assertEqual(csv_row["package"], "'@scope/demo@1.5.0")

    def test_csv_export_neutralizes_formulas(self):
        self.project()
        self.scan("--source", self.feed("pkg:npm/demo@1.5.0?source==HYPERLINK(1)"), "--export-csv", "out.csv")
        self.assertEqual(next(csv.DictReader(io.StringIO((self.root / "out.csv").read_text())))["source"], "'=HYPERLINK(1)")

    def test_issues_go_to_each_repository_and_skip_open_duplicates(self):
        self.project(name="packages/repo-a/package.json")
        self.write("packages/repo-b/package.json", json.dumps({"dependencies": {"other": "2.0.0"}}))
        feed = self.feed("pkg:npm/demo@1.5.0?ghsa=GHSA-aaaa&severity=moderate&source=ghsa",
                         "pkg:npm/demo@1.5.0?ghsa=GHSA-aaaa&severity=moderate&source=osv",
                         "pkg:npm/other@2.0.0?ghsa=GHSA-bbbb&severity=low")
        result = self.shell('''
            fetch_github_packages() { :; }; sleep() { :; }
            github_request() { case "$1" in *repo-a/issues*) printf '[{"title":"🟡 Security: 1 vulnerability in `demo` [MEDIUM]"}]';; *) printf '[]';; esac; }
            create_github_issue() { printf 'CREATE %s :: %s\\n' "$1" "$2"; }
            GITHUB_TOKEN=x main --github-org org --source ''' + str(feed) + ''' --create-multiple-issues --no-config''')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CREATE org/repo-b :: 🟢 Security: 1 vulnerability in `other` [LOW]", result.stdout)
        self.assertNotIn("CREATE org/repo-a", result.stdout)
        self.assertIn("Already open on org/repo-a", result.stdout)

    def test_rate_limit_waits_for_reset_header(self):
        result = self.shell('''
            sleep() { printf '%s' "$1" > waited; }
            date() { echo 1000; }
            curl() {
                local headers=""
                while [ $# -gt 0 ]; do [ "$1" = -D ] && headers="$2"; shift; done
                if [ -f waited ]; then printf '{}\\n200'; return; fi
                printf 'HTTP/2 403\\r\\nx-ratelimit-remaining: 0\\r\\nx-ratelimit-reset: 1042\\r\\n' > "$headers"
                printf '{"message":"API rate limit exceeded"}\\n403'
            }
            github_request https://api.github.invalid/test''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "waited").read_text(), "43")

    def test_failing_repository_does_not_stop_organization_fetch(self):
        result = self.shell('''
            sleep() { :; }
            GITHUB_ORG=org GITHUB_TOKEN=x
            get_github_repositories() { printf 'broken|org/broken\\nok|org/ok\\n'; }
            search_package_json_in_repo_tree() { [ "$2" = ok ] && echo "fetched $2"; }
            fetch_github_packages''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Skipping org/broken", result.stdout)
        self.assertIn("fetched ok", result.stdout)

class FeedRegressionTests(CheckerCase):
    def test_fetch_all_runs_ghsa_after_osv_failure(self):
        result = subprocess.run([BASH, "-c", 'source "$1"; fetch_osv() { echo osv; return 1; }; fetch_ghsa() { echo ghsa; }; fetch_all out',
                                 "test", str(SCRIPT)], cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn("ghsa", result.stdout)

    def test_fetch_osv_accepts_a_directory(self):
        result = subprocess.run([BASH, "-c", 'source "$1"; check_dependencies() { :; }; fetch_osv() { printf "%s|%s" "$FEED_OUTPUT_DIR" "$*" > called; }; main --fetch-osv feeds/',
                                 "test", str(SCRIPT)], cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "called").read_text(), "feeds|")

    def test_project_data_directory_does_not_shadow_builtin_feeds(self):
        self.write("data/ghsa.purl", "pkg:npm/shadow@1.0.0\n")
        result = subprocess.run([BASH, "-c", 'source "$1"; find_default_source ghsa.purl', "test", str(SCRIPT)],
                                cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout.strip(), str(ROOT / "data" / "ghsa.purl"))

class PrefilterRegressionTests(CheckerCase):
    def report(self, project, feed, prefilter):
        env = dict(os.environ)
        if not prefilter:
            env["PACKAGE_CHECKER_NO_PREFILTER"] = "1"
        out = self.root / ("on.json" if prefilter else "off.json")
        result = subprocess.run([BASH, str(SCRIPT), str(project), "--no-config", "--source", str(feed), "--export-json", str(out)],
                                cwd=self.root, env=env, text=True, capture_output=True, timeout=60)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return result.stdout, json.loads(out.read_text())["vulnerabilities"]

    def test_prefilter_never_drops_a_finding(self):
        fixtures = ROOT / "test-fixtures"
        for project in sorted(p for p in fixtures.iterdir() if p.is_dir()):
            for feed in ["test-vulnerabilities-multi.purl", "test-vulnerabilities.purl"]:
                with self.subTest(project=project.name, feed=feed):
                    _, filtered = self.report(project, fixtures / feed, True)
                    _, unfiltered = self.report(project, fixtures / feed, False)
                    self.assertEqual(filtered, unfiltered)

    def test_prefilter_reports_relevant_entries(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0", "pkg:npm/unrelated@1.0.0", "pkg:pypi/other@1.0.0")
        output, rows = self.report(self.root, feed, True)
        self.assertIn("1 relevant to this project (of 3 entries loaded)", output)
        self.assertEqual(len(rows), 1)

class AuditRegressionTests(CheckerCase):
    def shell(self, body):
        return subprocess.run([BASH, "-c", 'source "$1"; ' + body, "test", str(SCRIPT)],
                              cwd=self.root, text=True, capture_output=True, timeout=30)

    @unittest.skipIf(os.geteuid() == 0, "root can read any file")
    def test_unreadable_project_file_disables_prefilter(self):
        self.project()
        locked = self.write("locked/package-lock.json", "{}")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o644)
        result = self.shell('LOCKFILES="./locked/package-lock.json"; PACKAGE_JSON_FILES="./package.json"; '
                            'build_project_tokens; printf "[%s]" "$PREFILTER_TOKENS_FILE"')
        self.assertEqual(result.stdout, "[]", result.stderr)

    def test_prefilter_reads_many_files_and_extra_names(self):
        for i in range(50):
            self.write("p%d/package.json" % i, json.dumps({"dependencies": {"dep-%d" % i: "1.0.0"}}))
        files = "\\n".join("./p%d/package.json" % i for i in range(50))
        result = self.shell('PACKAGE_JSON_FILES=$\'' + files + '\'; LOCKFILES=""; build_project_tokens extra-name; '
                            'grep -cxE "dep-(0|49)|extra-name" "$PREFILTER_TOKENS_FILE"')
        self.assertEqual(result.stdout.strip(), "3", result.stderr)

    def test_fetch_keeps_a_directory_it_did_not_create(self):
        self.write("packages/repo/own-work.txt", "keep me\n")
        body = '''
            github_request() { printf '{"default_branch":"main","tree":[{"path":"package.json"}]}'; }
            curl() { printf '{}'; }
            search_package_json_in_repo_tree org/repo repo'''
        self.assertEqual(self.shell(body).returncode, 0)
        self.assertTrue((self.root / "packages/repo/own-work.txt").exists())
        self.assertTrue((self.root / "packages/repo/package.json").exists())
        (self.root / "packages/repo/stale.json").write_text("{}")
        (self.root / "packages/repo/own-work.txt").unlink()
        self.assertEqual(self.shell(body).returncode, 0)
        self.assertFalse((self.root / "packages/repo/stale.json").exists())

    def test_reusable_workflow_keeps_the_script_out_of_the_workspace(self):
        workflow = (ROOT / ".github/workflows/reusable-check.yml").read_text()
        self.assertIn('-o "$RUNNER_TEMP/package-checker/package-checker.sh"', workflow)
        self.assertNotIn("$GITHUB_WORKSPACE/package-checker.sh", workflow)

class MatchingGapRegressionTests(CheckerCase):
    """False negatives (and one false positive) found while adding runtime checks."""

    def test_go_sum_capitals_survive_the_prefilter(self):
        self.write("go.sum", "github.com/mojocn/base64!captcha v1.3.5 h1:x=\n")
        output = self.scan("--source", self.feed("pkg:golang/github.com/mojocn/base64Captcha@<1.3.6?ghsa=GHSA-captcha"))
        self.assertIn("github.com/mojocn/base64Captcha@1.3.5", output)

    def test_pub_build_metadata_orders_versions(self):
        self.write("pubspec.lock", "packages:\n  jose:\n    dependency: direct main\n    description:\n"
                   "      name: jose\n    source: hosted\n    version: \"0.3.5\"\n")
        feed = self.feed("pkg:pub/jose@<0.3.5+1?ghsa=GHSA-jose")
        self.assertIn("jose@0.3.5", self.scan("--source", feed))
        self.write("pubspec.lock", "packages:\n  jose:\n    dependency: direct main\n    description:\n"
                   "      name: jose\n    source: hosted\n    version: \"0.3.5+1\"\n")
        self.scan("--source", feed, code=0)

    def test_wildcard_sources_match_names_loosely(self):
        self.write("requirements.txt", "django==3.2.0\nzope.interface==5.0.0\n")
        csv_source = self.write("vulns.csv", "name,versions\nDjango,3.2.0\nzope_interface,5.0.0\n")
        output = self.scan("--source", csv_source)
        self.assertIn("django@3.2.0", output)
        self.assertIn("zope-interface@5.0.0", output)
        json_source = self.write("vulns.json", json.dumps({"Django": {"versions": ["3.2.0"]}}))
        self.assertIn("django@3.2.0", self.scan("--source", json_source))
        trivy = self.write("report.trivy.json", json.dumps({"Results": [{"Vulnerabilities": [
            {"PkgName": "Django", "InstalledVersion": "3.2.0", "VulnerabilityID": "CVE-2021-1", "Severity": "HIGH"}]}]}))
        self.assertIn("CVE-2021-1", self.scan("--source", trivy))

    def test_percent_encoded_purl_versions(self):
        sbom = self.write("bom.json", json.dumps({"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:golang/github.com/foo/bar@v1.2.3%2Bincompatible"}]}))
        feed = self.feed("pkg:golang/github.com/foo/bar@1.2.3%2Bincompatible?ghsa=GHSA-bar")
        self.assertIn("github.com/foo/bar@1.2.3+incompatible", self.scan("--sbom", sbom, "--source", feed))

    def test_gitignored_lockfiles_are_listed_and_can_be_included(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        self.write(".gitignore", "vendored/\n")
        self.project(name="vendored/package.json")
        feed = self.feed("pkg:npm/demo@1.5.0")
        output = self.scan("--source", feed, code=0)
        self.assertIn("Skipping 1 git-ignored file(s)", output)
        self.assertIn("vendored/package.json", output)
        self.assertIn("demo@1.5.0", self.scan("--source", feed, "--include-gitignored"))

    def test_maven_package_name_in_purl_form(self):
        feed = self.feed("pkg:maven/org.example/lib@1.0.0?ghsa=GHSA-lib")
        output = self.scan("--source", feed, "--package-name", "org.example/lib", "--ecosystem", "maven", "--package-version", "1.0.0")
        self.assertIn("GHSA-lib", output)

    def test_custom_source_range_dialects(self):
        cases = [
            ("composer", "vendor/pkg", "2.0.5", "<1.0|>=2.0,<2.1", True),
            ("composer", "vendor/pkg", "1.5.0", "~1.2", True),
            ("npm", "demo", "1.5.0", "~1.2", False),
            ("npm", "demo", "1.5.0", ">=1.0.0 !=1.5.0 <2.0.0", False),
            ("npm", "demo", "1.4.0", ">=1.0.0 != 1.5.0 <2.0.0", True),
            ("pypi", "demo", "2.9", "~=2.2", True),
            ("gem", "demo", "2.2.9", "~> 2.2.0", True),
            ("gem", "demo", "2.3.0", "~> 2.2.0", False),
            ("npm", "demo", "1.9.9", "1.x", True),
            ("npm", "demo", "1.5.0", "^1.x", True),
            ("pypi", "demo", "1.0.5", "==1.0.*", True),
            ("npm", "demo", "2.3.4", "1.2.3 - 2.3.4", True),
            ("npm", "demo", "2.3.5", "1.2.3 - 2.3.4", False),
            ("maven", "org.example:lib", "1.5", "[1.0,2.0)", True),
            ("maven", "org.example:lib", "2.0", "[1.0,2.0)", False),
            ("maven", "org.example:lib", "1.0", "(,1.0]", True),
            ("maven", "org.example:lib", "1.0", "[1.0]", True),
            ("nuget", "demo", "2.2", "[1.0,1.5),[2.0,2.5)", True),
            ("nuget", "demo", "1.7", "[1.0,1.5),[2.0,2.5)", False),
        ]
        for eco, name, version, constraint, expected in cases:
            with self.subTest(eco=eco, version=version, constraint=constraint):
                result = subprocess.run([BASH, "-c", 'source "$1"; CHECK_ECO="$2"; version_in_range "$3" "$4"', "test", str(SCRIPT), eco, version, constraint],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected, result.stderr)
                self.assertNotIn("unsupported", result.stderr)
        # End to end: an interval from a purl source, a composer OR range.
        self.write("composer.lock", json.dumps({"packages": [{"name": "vendor/pkg", "version": "2.0.5"}]}))
        self.assertIn("vendor/pkg@2.0.5", self.scan("--source", self.feed("pkg:composer/vendor/pkg@<1.0|>=2.0,<2.1")))
        self.write("composer.lock", json.dumps({"packages": [{"name": "vendor/pkg", "version": "1.0"}]}))
        self.assertIn("vendor/pkg@1.0", self.scan("--source", self.feed("pkg:composer/vendor/pkg@[1.0]")))

    def test_every_committed_feed_range_still_parses(self):
        import re
        exemplars = {}
        for feed in sorted((ROOT / "data").glob("*.purl")):
            with open(feed) as handle:
                for line in handle:
                    version = line.split("?", 1)[0].rsplit("@", 1)[-1]
                    if any(c in version for c in " <>=,^~*|"):
                        # One exemplar per shape (versions replaced by V)
                        exemplars.setdefault(re.sub(r"[0-9A-Za-z][0-9A-Za-z._+-]*", "V", version), version)
        self.assertTrue(exemplars)
        result = subprocess.run([BASH, "-c", 'source "$1"; shift; for r; do _prepare_range "$r" "npm|$r"; '
                                 '[ "${RANGE_CACHE[npm|$r]}" != "!" ] || echo "unparsed: $r"; done', "test", str(SCRIPT), *exemplars.values()],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.stdout + result.stderr, "")

    def test_bun_lock_nested_dependency_pins_are_not_installed_versions(self):
        self.write("bun.lock", '{\n  "lockfileVersion": 1,\n  "packages": {\n'
                   '    "minimist": ["minimist@1.2.8", "", {}, "sha512-x"],\n\n'
                   '    "mkdirp": ["mkdirp@0.5.1", "", { "dependencies": { "minimist": "0.0.8" } }, "sha512-y"],\n  }\n}\n')
        output = self.scan("--source", self.feed("pkg:npm/minimist@0.0.8", "pkg:npm/mkdirp@0.5.1"))
        self.assertIn("mkdirp@0.5.1", output)
        self.assertNotIn("minimist@0.0.8", output)

    def test_csv_metadata_columns(self):
        self.write("requirements.txt", "django==3.2.0\n")
        source = self.write("vulns.csv", "name,versions,severity,cve,source\nDjango,3.2.0,High,CVE-2021-31542,internal\n")
        output = self.scan("--source", source)
        self.assertIn("Severity: high", output)
        self.assertIn("CVE-2021-31542", output)
        self.assertIn("Source: internal", output)

    def test_unreadable_lockfile_is_an_error_not_a_clean_result(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        path = self.write("yarn.lock", 'demo@^1.0.0:\n  version "1.5.0"\n')
        path.chmod(0)
        self.addCleanup(path.chmod, 0o644)
        output = self.scan("--source", self.feed("pkg:npm/other@1.0.0"), code=2)
        self.assertIn("Cannot read this file", output)
        self.assertNotIn("[./yarn.lock] No vulnerabilities found", output)

    def test_yarn_version_is_read_at_the_entry_level(self):
        self.write("yarn.lock", 'demo@^1.0.0:\n  version "1.5.0"\n  dependencies:\n    version "^2.0.0"\n')
        output = self.scan("--source", self.feed("pkg:npm/demo@1.5.0"))
        self.assertIn("demo@1.5.0", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
