"""Regressions found by the November 2026 audit: missed packages and false clean scans."""
import json
import subprocess

from test_regressions import BASH, SCRIPT, CheckerCase


class AuditCase(CheckerCase):
    def findings(self, filename, document, *purls, code=1):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(document, bytes):
            path.write_bytes(document)
        else:
            path.write_text(document)
        self.scan("--source", self.feed(*purls), "--export-json", "out.json", "--no-runtime-check", code=code)
        return {row["package"] for row in json.loads((self.root / "out.json").read_text())["vulnerabilities"]}

    def shell(self, body, code=0):
        result = subprocess.run([BASH, "-c", 'source "$1"; ' + body, "test", str(SCRIPT)],
                                cwd=self.root, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout


class DiscoveryTests(AuditCase):
    def test_empty_ignore_paths_do_not_hide_every_file(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0")
        for ignore_paths in ('[""]', "[ ]", '["", "vendor"]'):
            with self.subTest(ignore_paths=ignore_paths):
                self.write("config.json", '{"options":{"ignore_paths":' + ignore_paths + "}}")
                self.assertIn("demo@1.5.0", self.scan("--source", feed, "--config", "config.json"))

    def test_failed_discovery_is_not_a_clean_scan(self):
        self.project()
        feed = self.feed("pkg:npm/demo@1.5.0")
        output = self.shell('find() { echo "find: broken expression" >&2; return 1; }; '
                            'main --source "' + str(feed) + '" --no-config', code=2)
        self.assertNotIn("No vulnerable packages detected", output)

    def test_summary_keeps_versions_containing_spaces(self):
        self.write("bom.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": "demo", "version": "1.0 beta", "purl": "pkg:npm/demo@1.0%20beta"}]}))
        self.write("vulns.json", '{"demo":{"versions":["1.0 beta"]}}')
        output = self.scan("--sbom", "bom.json", "--source", "vulns.json")
        summary = output[output.index("SUMMARY"):]
        self.assertIn("demo@1.0 beta", summary)
        self.assertIn("└─ bom.json", summary)
        self.assertNotIn("[beta]", summary)


class ParserTests(AuditCase):
    def test_requirements_bom_does_not_hide_the_first_pin(self):
        self.assertEqual(self.findings("requirements.txt", b"\xef\xbb\xbfdemo==1.5.0\r\nother==1.0\r\n",
                                       "pkg:pypi/demo@1.5.0"), {"demo@1.5.0"})

    def test_requirements_comment_continuation_and_last_line(self):
        document = "first==1.0\n# note ending with a backslash \\\ndemo==1.5.0\nlast==2.0 \\\n"
        self.assertEqual(self.findings("requirements.txt", document, "pkg:pypi/demo@1.5.0", "pkg:pypi/last@2.0"),
                         {"demo@1.5.0", "last@2.0"})

    def test_gemfile_lock_and_go_sum_tolerate_a_bom(self):
        gem = b"\xef\xbb\xbfGEM\n  remote: https://rubygems.org/\n  specs:\n    demo (1.5.0)\n\nPLATFORMS\n  ruby\n"
        self.assertEqual(self.findings("Gemfile.lock", gem, "pkg:gem/demo@1.5.0"), {"demo@1.5.0"})
        go = b"\xef\xbb\xbfexample.com/demo v1.5.0 h1:abc=\nexample.com/demo v1.5.0/go.mod h1:def=\n"
        self.assertEqual(self.findings("sub/go.sum", go, "pkg:golang/example.com/demo@1.5.0"),
                         {"example.com/demo@1.5.0"})

    def test_pnpm_legacy_git_and_tarball_packages(self):
        lock = """lockfileVersion: '6.0'

packages:

  /plain@1.0.0:
    resolution: {integrity: sha512-x}
    dev: false

  github.com/owner/demo/97edff6f525f192a3f83cea1944765f769ae2678:
    resolution: {tarball: https://codeload.github.com/owner/demo/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678}
    name: demo
    version: 1.5.0
    dev: false

  registry.npmjs.org/tarball/-/tarball-2.0.0.tgz:
    resolution: {tarball: https://registry.npmjs.org/tarball/-/tarball-2.0.0.tgz}
    name: '@scope/tarball'
    version: 2.0.0
    dependencies:
      plain: 1.0.0
    dev: false
"""
        self.assertEqual(self.findings("pnpm-lock.yaml", lock, "pkg:npm/demo@1.5.0",
                                       "pkg:npm/%40scope/tarball@2.0.0", "pkg:npm/plain@1.0.0"),
                         {"demo@1.5.0", "@scope/tarball@2.0.0", "plain@1.0.0"})

    def test_go_mod_replace_selects_the_built_version(self):
        mod = """module example.com/app

go 1.21

require (
\texample.com/demo v1.0.0
\texample.com/kept v1.0.0
\texample.com/forked v1.0.0
\texample.com/local v1.0.0
)

replace example.com/demo => example.com/demo v1.5.0

replace (
\texample.com/forked v1.0.0 => example.com/fork v2.0.0
\texample.com/local => ../local
)
"""
        found = self.findings("go.mod", mod, "pkg:golang/example.com/demo@1.5.0", "pkg:golang/example.com/demo@1.0.0",
                              "pkg:golang/example.com/kept@1.0.0", "pkg:golang/example.com/fork@2.0.0",
                              "pkg:golang/example.com/forked@1.0.0", "pkg:golang/example.com/local@1.0.0")
        self.assertEqual(found, {"example.com/demo@1.5.0", "example.com/kept@1.0.0", "example.com/fork@2.0.0"})

    def test_workflow_flow_mapping_steps(self):
        workflow = """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - {name: flow, uses: owner/demo@v1.5.0}
      - { uses: "owner/quoted@v2.0.0", with: {a: b} }
      - uses: owner/block@v3.0.0
"""
        self.assertEqual(self.findings(".github/workflows/ci.yml", workflow, "pkg:githubactions/owner/demo@1.5.0",
                                       "pkg:githubactions/owner/quoted@2.0.0", "pkg:githubactions/owner/block@3.0.0"),
                         {"owner/demo@1.5.0", "owner/quoted@2.0.0", "owner/block@3.0.0"})

    def test_deno_lock_reads_only_npm_packages(self):
        lock = {"version": "4",
                "specifiers": {"jsr:@std/path@1": "1.0.8", "npm:demo@1": "1.5.0"},
                "jsr": {"@std/path@1.0.8": {"integrity": "abc"}},
                "npm": {"demo@1.5.0": {"integrity": "sha512-x"},
                        "@scope/peer@2.0.0_demo@1.5.0": {"integrity": "sha512-y"}},
                "remote": {"https://deno.land/std@0.200.0/path/mod.ts": "hash"}}
        purls = ["pkg:npm/demo@1.5.0", "pkg:npm/%40scope/peer@2.0.0", "pkg:npm/%40std/path@1.0.8"]
        for label, document in (("pretty", json.dumps(lock, indent=2)), ("compact", json.dumps(lock))):
            with self.subTest(layout=label):
                self.assertEqual(self.findings("deno.lock", document, *purls), {"demo@1.5.0", "@scope/peer@2.0.0"})

    def test_deno_lock_v3_packages_section(self):
        lock = {"version": "3", "packages": {"specifiers": {"npm:demo@1": "npm:demo@1.5.0"},
                                             "jsr": {"@std/path@1.0.8": {"integrity": "abc"}},
                                             "npm": {"demo@1.5.0": {"integrity": "sha512-x", "dependencies": {}}}}}
        self.assertEqual(self.findings("deno.lock", json.dumps(lock, indent=2), "pkg:npm/demo@1.5.0",
                                       "pkg:npm/%40std/path@1.0.8"), {"demo@1.5.0"})


class JsonAccessorTests(AuditCase):
    def accessor(self, function, document, *args):
        self.write("doc.json", document)
        return self.shell(function + ' "$(cat doc.json)" ' + " ".join(args)).rstrip("\n")

    def test_key_is_matched_at_the_top_level_only(self):
        document = '{"keywords": ["engines"], "nested": {"engines": {"node": "1"}}, "engines": {"node": ">=18"}}'
        self.assertEqual(json.loads(self.accessor("json_get_object", document, "engines")), {"node": ">=18"})
        self.assertEqual(self.accessor("json_get_value", '{"a": {"org": "inner"}, "org": "outer"}', "org"), "outer")
        self.assertEqual(self.accessor("json_get_object", '{"a": 1}', "missing"), "{}")
        self.assertEqual(self.accessor("json_get_array", '{"a": 1}', "missing"), "[]")

    def test_escaped_backslash_closes_its_string(self):
        document = json.dumps({"scripts": {"x": "C:\\"}, "engines": {"node": "20"}})
        self.assertEqual(json.loads(self.accessor("json_get_object", document, "engines")), {"node": "20"})
        items = self.accessor("json_array_items", json.dumps(["a\\", "b", {"k": [1, 2]}, "c"])).splitlines()
        self.assertEqual([json.loads(item) for item in items], ["a\\", "b", {"k": [1, 2]}, "c"])

    def test_scalars_and_string_escapes(self):
        document = json.dumps({"path": "C:\\data\\feed.json", "ratio": 1.5, "on": False, "none": None})
        self.assertEqual(self.accessor("json_get_value", document, "path"), "C:\\data\\feed.json")
        self.assertEqual(self.accessor("json_get_value", document, "ratio"), "1.5")
        self.assertEqual(self.accessor("json_get_value", document, "on"), "false")
        self.assertEqual(self.accessor("json_get_value", document, "none"), "null")
        self.assertEqual(self.accessor("json_get_value", '{"url": "a\\/b"}', "url"), "a/b")

    def test_pretty_and_compact_documents_agree(self):
        config = {"sources": [{"source": "a.purl", "name": "A"}, {"url": "b.json"}], "options": {"ignore_paths": ["x"]}}
        for document in (json.dumps(config), json.dumps(config, indent=4)):
            array = self.accessor("json_get_array", document, "sources")
            items = self.accessor("json_array_items", array).splitlines()
            self.assertEqual([json.loads(item) for item in items], config["sources"])

    def test_branch_commit_is_pinned_by_its_own_sha(self):
        output = self.shell('''
            github_request() {
                case "$1" in
                    */branches/main) echo '{"name":"main","commit":{"sha":"0123456789abcdef0123456789abcdef01234567","commit":{"tree":{"sha":"ffffffffffffffffffffffffffffffffffffffff"}}}}' ;;
                    */git/trees/*) echo "TREE $1" >&2; echo '{"tree":[],"truncated":false}' ;;
                    *) echo '{"parent":{"default_branch":"other"},"default_branch":"main"}' ;;
                esac
            }
            search_package_json_in_repo_tree org/repo repo 2>&1''')
        self.assertIn("/git/trees/0123456789abcdef0123456789abcdef01234567?", output)
