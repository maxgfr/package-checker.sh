"""Runtime version check (Node.js / PHP) against a fixed runtime feed."""
import json
import shutil
import subprocess

from test_regressions import BASH, SCRIPT, CheckerCase

# Node2Shell and PHP2Shell, as fetch_runtime emits them from OSV Bitnami.
RUNTIME_FEED = "\n".join([
    "pkg:runtime/node@>=0 <22.23.4?severity=critical&cve=CVE-2026-111497&id=BIT-node-2026-111497&source=osv",
    "pkg:runtime/node@>=23.0.0 <24.22.1?severity=critical&cve=CVE-2026-111497&id=BIT-node-2026-111497&source=osv",
    "pkg:runtime/node@>=26.0.0 <26.12.1?severity=critical&cve=CVE-2026-111497&id=BIT-node-2026-111497&source=osv",
    "pkg:runtime/php@>=0 <8.2.35?severity=critical&cve=CVE-2026-109618&id=BIT-php-2026-109618&source=osv",
    "pkg:runtime/php@>=8.3.0 <8.3.36?severity=critical&cve=CVE-2026-109618&id=BIT-php-2026-109618&source=osv",
    "pkg:runtime/php@>=8.4.0 <8.4.27?severity=critical&cve=CVE-2026-109618&id=BIT-php-2026-109618&source=osv",
    "pkg:runtime/php@>=8.5.0 <8.5.12?severity=critical&cve=CVE-2026-109618&id=BIT-php-2026-109618&source=osv",
]) + "\n"


class RuntimeTests(CheckerCase):
    def setUp(self):
        super().setUp()
        # A copy of the script finds data/ next to itself first: the real feed
        # (refreshed every 12h) cannot change these results.
        self.bin = self.root / "bin"
        (self.bin / "data").mkdir(parents=True)
        shutil.copy(SCRIPT, self.bin / "script.sh")
        (self.bin / "data" / "osv-runtime.purl").write_text(RUNTIME_FEED)
        self.project_dir = self.root / "project"
        self.project_dir.mkdir()
        # A custom source: no default GHSA feed is needed (or downloaded).
        self.source = self.write("feed.purl", "pkg:npm/unrelated@1.0.0\n")

    def put(self, name, content):
        path = self.project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def run_checker(self, *args, code):
        result = subprocess.run(
            [BASH, str(self.bin / "script.sh"), "--source", str(self.source), *map(str, args)],
            cwd=self.project_dir, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def test_vulnerable_nvmrc_is_a_finding(self):
        self.put(".nvmrc", "v22.1.0\n")
        output = self.run_checker(code=1)
        self.assertIn("[runtime] node@22.1.0", output)
        self.assertIn("CVE-2026-111497", output)
        self.assertIn("Fix: upgrade to >= 22.23.4", output)

    def test_fixed_nvmrc_is_clean(self):
        self.put(".nvmrc", "22.23.4\n")
        output = self.run_checker(code=0)
        self.assertIn("Runtime versions: no known vulnerability", output)

    def test_eol_docker_line_warns_without_failing(self):
        self.put("Dockerfile", "FROM --platform=linux/amd64 node:20-alpine AS build\n")
        output = self.run_checker(code=0)
        self.assertIn("Node.js 20: no release of this line fixes CVE-2026-111497; move to >= 22.23.4", output)
        self.assertIn("No vulnerable packages detected", output)

    def test_patched_docker_line_is_quiet(self):
        self.put("Dockerfile", "FROM node:22-bookworm-slim\n")
        self.assertNotIn("Node.js 22", self.run_checker(code=0))

    def test_engines_range_warns_with_the_fix(self):
        self.put("package.json", json.dumps({"engines": {"node": ">=18"}}))
        output = self.run_checker(code=0)
        self.assertIn("Node.js >=18 allows vulnerable versions (CVE-2026-111497); raise the minimum to >= 22.23.4", output)

    def test_composer_platform_php_is_a_finding(self):
        self.put("composer.json", json.dumps({"require": {"php": ">=8.3.36"}, "config": {"platform": {"php": "8.3.10"}}}))
        output = self.run_checker(code=1)
        self.assertIn("[runtime] php@8.3.10", output)
        self.assertIn("CVE-2026-109618", output)
        self.assertNotIn("allows vulnerable versions", output)

    def test_fixed_php_image_is_clean(self):
        self.put("Dockerfile", "FROM php:8.4.27-fpm\n")
        self.run_checker(code=0)

    def test_other_runtime_sources(self):
        cases = {
            ".node-version": "24.22.0\n",
            ".tool-versions": "python 3.12.0\nnodejs 24.22.0\n",
            ".php-version": "8.4.26\n",
            "composer.lock": json.dumps({"packages": [], "platform-overrides": {"php": "8.4.26"}}),
            "package.json": json.dumps({"volta": {"node": "24.22.0"}}),
            ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: shivammathur/setup-php@v2\n"
                                        "        with:\n          php-version: '8.4.26'\n",
        }
        for name, content in cases.items():
            with self.subTest(file=name):
                self.put(name, content)
                output = self.run_checker(code=1)
                self.assertRegex(output, r"\[runtime\] (node@24\.22\.0|php@8\.4\.26)")
                (self.project_dir / name).unlink()

    def test_workflow_matrix_lists(self):
        self.put(".github/workflows/ci.yml", "jobs:\n  t:\n    strategy:\n      matrix:\n"
                 "        node-version: [20.x, '24.22.1']\n        php-version:\n          - 8.1\n          - \"8.4.27\"\n"
                 "    steps:\n      - uses: actions/setup-node@v4\n        with:\n"
                 "          node-version: ${{ matrix.node-version }}\n")
        output = self.run_checker(code=0)
        self.assertIn("Node.js 20: no release of this line fixes", output)
        self.assertIn("PHP 8.1: no release of this line fixes CVE-2026-109618; move to >= 8.2.35", output)

    def test_unresolvable_values_are_ignored(self):
        self.put(".nvmrc", "lts/*\n")
        self.put("Dockerfile", "ARG V=22\nFROM node:${V}\nFROM node:lts-alpine\nFROM php\n")
        output = self.run_checker(code=0)
        self.assertIn("Runtime versions: no known vulnerability", output)

    def test_runtime_check_can_be_disabled(self):
        self.put(".nvmrc", "22.1.0\n")
        output = self.run_checker("--no-runtime-check", code=0)
        self.assertNotIn("runtime", output.lower().replace("--no-runtime-check", ""))
        self.put(".package-checker.config.json", json.dumps({"options": {"runtime_check": False}}))
        self.assertNotIn("node@22.1.0", self.run_checker(code=0))

    def test_only_lockfiles_still_checks_runtimes(self):
        self.put(".nvmrc", "22.1.0\n")
        self.assertIn("[runtime] node@22.1.0", self.run_checker("--only-lockfiles", code=1))

    def test_package_name_lookup_of_a_runtime(self):
        result = subprocess.run(
            [BASH, str(self.bin / "script.sh"), "--package-name", "node", "--ecosystem", "runtime", "--package-version", "22.1.0"],
            cwd=self.project_dir, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CVE-2026-111497", result.stdout)

    def test_runtime_finding_is_exported(self):
        self.put(".nvmrc", "22.1.0\n")
        self.run_checker("--export-json", "out.json", code=1)
        data = json.loads((self.project_dir / "out.json").read_text())
        rows = data if isinstance(data, list) else data.get("vulnerabilities", [])
        self.assertTrue(any(r.get("ecosystem") == "runtime" and r.get("package", "").startswith("node") for r in rows), data)


if __name__ == "__main__":
    import unittest
    unittest.main(verbosity=2)
