"""Exercise actual curl against a local server, and GitHub with shell mocks."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
import threading
import unittest

from test_regressions import BASH, SCRIPT, CheckerCase


class NetworkTests(CheckerCase):
    def local_server(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                data = b"pkg:npm/demo@1.5.0\n"
                if self.path == "/redirect.purl":
                    self.send_response(302)
                    self.send_header("Location", "/feed.purl")
                    self.end_headers()
                    return
                self.send_response(404 if self.path == "/missing.purl" else 200)
                self.send_header("Content-Length", str(len(data) + (50 if self.path == "/partial.purl" else 0)))
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:" + str(server.server_port)

    def test_http_redirect_downloads_source(self):
        self.project()
        self.assertIn("demo@1.5.0", self.scan("--source", self.local_server() + "/redirect.purl"))

    def test_http_error_rejects_body(self):
        self.project()
        output = self.scan("--source", self.local_server() + "/missing.purl")
        self.assertIn("Unable to download", output)
        self.assertNotIn("SUMMARY", output)

    def test_partial_download_fails(self):
        self.project()
        self.assertIn("Unable to download", self.scan("--source", self.local_server() + "/partial.purl"))

    def shell(self, body, code=0):
        result = subprocess.run([BASH, "-c", 'source "$1"; ' + body, "test", str(SCRIPT)], cwd=self.root, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def test_github_rate_limit_retries(self):
        output = self.shell('''
            sleep() { :; }
            curl() {
                if [ -f retried ]; then printf '{"ok":true}\\n200';
                else touch retried; printf '{"message":"rate limit"}\\n429'; fi
            }
            github_request https://api.github.invalid/test
        ''')
        self.assertEqual(json.loads(output), {"ok": True})

    def test_github_error_propagates(self):
        self.shell('curl() { printf \'{"message":"Not Found"}\\n404\'; }; github_request https://api.github.invalid/test', code=1)

    def test_github_transport_failure_propagates(self):
        self.shell('curl() { return 7; }; github_request https://api.github.invalid/test', code=1)

    def test_github_empty_tree_is_success(self):
        self.shell('''
            github_request() { printf '{"default_branch":"main","tree":[],"truncated":false}'; }
            search_package_json_in_repo_tree org/repo repo
        ''')

    def test_github_truncated_tree_fails(self):
        self.shell('''
            github_request() { printf '{"default_branch":"main","tree":[],"truncated":true}'; }
            search_package_json_in_repo_tree org/repo repo
        ''', code=1)

    def test_github_download_failure_does_not_save_error_body(self):
        self.shell('''
            github_request() { printf '{"default_branch":"main","tree":[{"path":"package.json"}]}'; }
            curl() { printf 'error body'; return 22; }
            search_package_json_in_repo_tree org/repo repo
        ''', code=1)
        self.assertFalse((self.root / "packages/repo/package.json").exists())

    def test_github_download_preserves_subdirectory(self):
        self.shell('''
            github_request() { printf '{"default_branch":"main","tree":[{"path":"nested/package.json"},{"path":"notpackage.json"}]}'; }
            curl() { printf '{"dependencies":{"demo":"1.5.0"}}'; }
            search_package_json_in_repo_tree org/repo repo
        ''')
        self.assertTrue((self.root / "packages/repo/nested/package.json").exists())
        self.assertFalse((self.root / "packages/repo/notpackage.json").exists())

    def test_config_github_settings_are_loaded_before_fetch(self):
        self.write("config.json", '{"github":{"repo":"org/config-repo","output":"fetched"}}')
        output = self.shell('''
            fetch_github_packages() { printf 'REPO=%s OUTPUT=%s\\n' "$GITHUB_REPO" "$GITHUB_OUTPUT_DIR"; }
            main --config config.json --github-only
        ''')
        self.assertIn("REPO=org/config-repo OUTPUT=fetched", output)

    def test_rate_limit_without_message_is_retried(self):
        self.shell('''
            sleep() { :; }
            curl() {
                if [ -f retried ]; then printf '{}\\n200';
                else touch retried; printf '{}\\n429'; fi
            }
            github_request https://api.github.invalid/test
        ''')

    def test_failed_ghsa_clone_preserves_previous_feed(self):
        self.write("feeds/ghsa.purl", "previous feed\n")
        self.shell('''
            FEED_OUTPUT_DIR="$PWD/feeds"
            git() { return 1; }
            fetch_ghsa npm
        ''', code=1)
        self.assertEqual((self.root / "feeds/ghsa.purl").read_text(), "previous feed\n")

    def test_failed_osv_download_preserves_previous_feed(self):
        self.write("feeds/osv.purl", "previous feed\n")
        self.shell('''
            FEED_OUTPUT_DIR="$PWD/feeds"
            curl() { return 22; }
            fetch_osv npm
        ''', code=1)
        self.assertEqual((self.root / "feeds/osv.purl").read_text(), "previous feed\n")

    def test_parallel_feed_emission_and_invalid_input(self):
        advisory = {"id": "GHSA-fixture", "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.0.0"]}]}
        self.write("advisories/one.json", json.dumps(advisory))
        self.shell('feed_emit_raw advisories ghsa \'{"npm":"npm"}\' result.purl')
        self.assertIn("pkg:npm/demo@1.0.0", (self.root / "result.purl").read_text())
        self.write("advisories/broken.json", "{bad json")
        self.shell('feed_emit_raw advisories ghsa \'{"npm":"npm"}\' result.purl', code=1)

    def test_issue_http_error_is_failure(self):
        self.shell('''
            GITHUB_TOKEN=test-placeholder
            curl() { printf '{"html_url":"https://github.invalid/profile","message":"denied"}\\n403'; }
            create_github_issue org/repo title body
        ''', code=1)

    def test_github_pagination(self):
        first = [{"name": "repo" + str(i), "full_name": "org/repo" + str(i)} for i in range(100)]
        self.write("page1.json", json.dumps(first))
        self.write("page2.json", '[{"name":"last","full_name":"org/last"}]')
        output = self.shell('''
            sleep() { :; }
            GITHUB_ORG=org
            github_request() {
                case "$1" in *page=1\&*) cat page1.json ;; *page=2\&*) cat page2.json ;; *) return 1 ;; esac
            }
            get_github_repositories
        ''')
        self.assertEqual(len(output.splitlines()), 101)
        self.assertIn("last|org/last", output)

    def test_issue_payload_is_escaped_and_failure_is_visible(self):
        self.shell('''
            GITHUB_TOKEN=test-placeholder
            curl() {
                while [ "$#" -gt 0 ]; do
                    if [ "$1" = -d ]; then printf '%s' "$2" > payload.json; break; fi
                    shift
                done
                printf '{"html_url":"https://github.invalid/issue/1"}\\n201'
            }
            create_github_issue org/repo 'Title "quoted"' $'Line one\\nLine two' 'security,dependencies'
        ''')
        payload = json.loads((self.root / "payload.json").read_text())
        self.assertEqual(payload["title"], 'Title "quoted"')
        self.assertEqual(payload["body"], "Line one\nLine two")
        self.assertEqual(payload["labels"], ["security", "dependencies"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
