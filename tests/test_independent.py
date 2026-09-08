"""Independent inputs: format invariants and package identities, no fixture copies."""
import hashlib
import json
import subprocess
import unittest

from test_regressions import BASH, SCRIPT, CheckerCase


class IndependentTests(CheckerCase):
    def test_json_structural_records_preserve_chunk_boundary_escapes(self):
        # Golden bytes captured before the streaming optimization: chunking
        # must not change record whitespace or escaped/Unicode string contents.
        digests = [
            "fab226af417289f6864ac44bb96f90b1dd16f9e14062dca086834e41a5ad0feb",
            "59a91e29ed6342c0d896ff6ea1bb39d5a88ad18aaa7238709d38304b8c62d8a9",
            "55f798357700954c3bf5b27016e0c1646f4daa73415b1506ca0b00735cda363f",
            "a526713ba0d95cb9af0e861aa6b3f9038aef000e8d9cb327426fc781ce46f4cf",
            "e6b442c99531c4dbed21472fe9a70a61fd38a9af9ed7a79c7191650549d418a8",
            "2e433fd7d527775a1cebdfea106442613d1fa49330223e68b3767cbf6845d4c5",
            "a6e780970e591153c676675d8bd4ce37155727605b3cc9357f6d6e1df5f1d0cd",
            "4e17e20e588f08234f8990d0737c29887bdeec2567c60a91b841176286aaaf5c",
        ]
        index = 0
        for indent in (None, 2):
            for padding in (4081, 4082, 4083, 4084):
                with self.subTest(indent=indent, padding=padding):
                    data = {"padding": "x" * padding, "escapes": '\\"{}[],é漢字',
                            "nested": [{"name": "demo", "version": "1.2.3"}, True, None, 1.25]}
                    filename = self.write("lock.json", json.dumps(data, indent=indent, ensure_ascii=False))
                    result = subprocess.run([BASH, "-c", 'source "$1"; json_structural_lines "$2"',
                                             "test", str(SCRIPT), str(filename)], capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), digests[index])
                    index += 1

    def findings(self, filename, document, *purls):
        self.write(filename, document)
        self.scan("--source", self.feed(*purls), "--export-json", "out.json")
        return {row["package"] for row in json.loads((self.root / "out.json").read_text())["vulnerabilities"]}

    def test_npm_v1_nested_dependencies(self):
        lock = {"lockfileVersion": 1, "dependencies": {
            "parent": {"version": "1.0.0", "dependencies": {
                "demo": {"version": "1.5.0"}}}}}
        self.assertEqual(self.findings("package-lock.json", json.dumps(lock, indent=2),
                                      "pkg:npm/demo@1.5.0"), {"demo@1.5.0"})

    def test_npm_modern_map_ignores_stale_legacy_tree_and_links(self):
        lock = {"lockfileVersion": 2, "packages": {
            "node_modules/demo": {"version": "2.0.0", "funding": {"version": "1.5.0"}},
            "node_modules/local": {"version": "1.5.0", "link": True}},
            "dependencies": {"demo": {"version": "1.5.0"}}}
        self.write("package-lock.json", json.dumps(lock))
        self.scan("--source", self.feed("pkg:npm/demo@1.5.0", "pkg:npm/local@1.5.0"), code=0)

    def test_npm_v1_alias_and_scoped_nested_identity(self):
        lock = {"lockfileVersion": 1, "dependencies": {"alias": {"version": "npm:@scope/demo@1.5.0"}}}
        self.assertEqual(self.findings("npm-shrinkwrap.json", json.dumps(lock),
                                      "pkg:npm/%40scope/demo@1.5.0"), {"@scope/demo@1.5.0"})

    def test_npm_json_serialization_preserves_packages(self):
        lock = {"name": "root", "version": "9.0.0", "lockfileVersion": 3,
                "packages": {"": {"version": "9.0.0"},
                             "node_modules/first": {"version": "1.0.0"},
                             "node_modules/demo": {"version": "1.5.0",
                                 "description": 'punctuation },[ and escaped quote " and backslash \\',
                                 "metadata": {"name": "wrong", "version": "8.0.0"}}}}
        for indent in [None, 2, 4]:
            with self.subTest(indent=indent):
                self.assertEqual(self.findings("package-lock.json", json.dumps(lock, indent=indent),
                                              "pkg:npm/demo@1.5.0", "pkg:npm/first@1.0.0"),
                                 {"demo@1.5.0", "first@1.0.0"})

    def test_npm_alias_uses_resolved_package_identity(self):
        lock = {"lockfileVersion": 3, "packages": {
            "node_modules/local-alias": {"name": "demo", "version": "1.5.0"}}}
        self.assertEqual(self.findings("package-lock.json", json.dumps(lock, indent=2),
                                      "pkg:npm/demo@1.5.0"), {"demo@1.5.0"})

    def test_pnpm_peer_resolutions_and_legacy_keys(self):
        for key in ["/demo/1.5.0", "/demo/1.5.0_peer@2.0.0", "/demo@1.5.0(peer@2.0.0)",
                    "demo@1.5.0", "demo@1.5.0(peer@2.0.0)"]:
            with self.subTest(key=key):
                lock = "lockfileVersion: '6.0'\npackages:\n  '" + key + "':\n    resolution: {integrity: sha512-test}\n"
                self.assertEqual(self.findings("pnpm-lock.yaml", lock, "pkg:npm/demo@1.5.0"),
                                 {"demo@1.5.0"})

    def test_pnpm_scopes_and_nested_metadata(self):
        for key in ["/@scope/demo/1.5.0_peer@2.0.0", "@scope/demo@1.5.0(peer@2.0.0)"]:
            with self.subTest(key=key):
                lock = "packages:\n  '" + key + "':\n    dependencies:\n      'wrong@1.5.0':\n        version: 1.5.0\n"
                self.assertEqual(self.findings("pnpm-lock.yaml", lock,
                                              "pkg:npm/%40scope/demo@1.5.0", "pkg:npm/wrong@1.5.0"),
                                 {"@scope/demo@1.5.0"})

    def test_hex_package_name_can_differ_from_application(self):
        lock = '%{\n  "application_alias": {:hex, :actual_package, "1.5.0", "checksum", [:mix], [], "hexpm", "checksum"},\n}\n'
        self.assertEqual(self.findings("mix.lock", lock, "pkg:hex/actual_package@1.5.0"),
                         {"actual_package@1.5.0"})
        self.scan("--source", self.feed("pkg:hex/application_alias@1.5.0"), code=0)

    def test_json_lockfiles_preserve_packages_when_compacted(self):
        rows = [
            ("composer.lock", {"packages": [{"name": "vendor/demo", "version": "1.5.0"}],
                               "packages-dev": [{"name": "vendor/dev", "version": "1.0.0"}]},
             ["pkg:composer/vendor/demo@1.5.0", "pkg:composer/vendor/dev@1.0.0"],
             {"vendor/demo@1.5.0", "vendor/dev@1.0.0"}),
            ("packages.lock.json", {"version": 1, "dependencies": {"net8.0": {
                "Demo": {"type": "Direct", "resolved": "1.5.0", "dependencies": {"Other": "2.0.0"}}}}},
             ["pkg:nuget/demo@1.5.0"], {"demo@1.5.0"}),
            ("Package.resolved", {"version": 2, "pins": [{"identity": "demo",
                "location": "https://github.com/example/demo.git", "state": {"version": "1.5.0"}}]},
             ["pkg:swift/github.com/example/demo@1.5.0"], {"github.com/example/demo@1.5.0"}),
            ("Pipfile.lock", {"_meta": {"pipfile-spec": 6}, "default": {
                "Demo": {"version": "==1.5.0", "hashes": ["sha256:test"]}}, "develop": {}},
             ["pkg:pypi/demo@1.5.0"], {"demo@1.5.0"}),
        ]
        for filename, lock, feed, expected in rows:
            for indent in [2, None]:
                with self.subTest(filename=filename, indent=indent):
                    self.assertEqual(self.findings(filename, json.dumps(lock, indent=indent), *feed), expected)
            (self.root / filename).unlink()

    def test_malformed_json_projects_are_not_clean_scans(self):
        for filename in ["package.json", "package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock",
                         "composer.lock", "packages.lock.json", "Package.resolved", "deno.lock"]:
            with self.subTest(filename=filename):
                self.write(filename, "{\"broken\":")
                output = self.scan("--source", self.feed("pkg:npm/demo@1.5.0"))
                self.assertIn("Invalid JSON", output)
                self.assertNotIn("No vulnerable packages detected", output)
                (self.root / filename).unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
