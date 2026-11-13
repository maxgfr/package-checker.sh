"""Audit regressions in feed resolution, CLI flags and GitHub scanning."""
import json
import os
import shutil
import subprocess

from test_audit import AuditCase
from test_regressions import BASH, FEED_RESOLVER_STUB, ROOT, SCRIPT


class FeedResolutionTests(AuditCase):
    def resolve(self, script, prelude=""):
        result = subprocess.run([BASH, "-c", 'source "$1"; BREW_PREFIX=""; ' + prelude + "; find_default_source ghsa.purl",
                                 "test", str(script)], cwd=self.root, text=True, capture_output=True, timeout=30)
        return result

    def test_project_data_does_not_replace_a_reachable_remote_feed(self):
        self.write("data/ghsa.purl", "pkg:npm/shadow@1.0.0\n")
        lone = self.root / "bin" / "script.sh"
        lone.parent.mkdir()
        shutil.copy(SCRIPT, lone)
        cache = self.root / "cache"
        stub = 'PACKAGE_CHECKER_CACHE_DIR="%s"; curl() { case " $* " in *" --head "*) return 0 ;; esac; echo "pkg:npm/remote@1.0.0"; }' % cache
        result = self.resolve(lone, stub)
        self.assertEqual(result.stdout.strip(), str(cache / "ghsa.purl"), result.stderr)
        self.assertEqual((cache / "ghsa.purl").read_text().splitlines()[1:], ["pkg:npm/remote@1.0.0"])

    def test_project_data_is_an_offline_last_resort_with_a_warning(self):
        self.write("data/ghsa.purl", "pkg:npm/shadow@1.0.0\n")
        lone = self.root / "bin" / "script.sh"
        lone.parent.mkdir()
        shutil.copy(SCRIPT, lone)
        result = self.resolve(lone, "curl() { return 7; }")
        self.assertEqual(result.stdout.strip(), "./data/ghsa.purl")
        self.assertIn("built-in feeds unreachable", result.stderr)

    def test_symlinked_script_finds_its_bundled_feeds(self):
        link = self.root / "package-checker"
        os.symlink(SCRIPT, link)
        result = self.resolve(link, "curl() { return 7; }")
        self.assertEqual(result.stdout.strip(), str(ROOT / "data" / "ghsa.purl"))

    def test_inherited_script_home_is_ignored(self):
        result = subprocess.run([BASH, "-c", 'source "$1"; find_default_source ghsa.purl', "test", str(SCRIPT)],
                                cwd=self.root, text=True, capture_output=True, timeout=30,
                                env=dict(os.environ, SCRIPT_HOME=str(self.root), BREW_PREFIX=str(self.root)))
        self.assertEqual(result.stdout.strip(), str(ROOT / "data" / "ghsa.purl"))

    def test_default_source_flags_add_up(self):
        self.project()
        self.write("empty.purl", "pkg:npm/other@1.0.0\n")
        prelude = FEED_RESOLVER_STUB + 'find_default_source() { printf "%s\\n" "$1" >> requested; printf "%s/empty.purl" "$PWD"; }'
        self.shell(prelude + "; main --no-config --default-source-ghsa --default-source-osv")
        self.assertEqual(sorted((self.root / "requested").read_text().split()), ["ghsa.purl", "osv.purl"])


class FetchArgumentTests(AuditCase):
    def test_ecosystem_name_wins_over_a_directory_of_that_name(self):
        (self.root / "go").mkdir()
        output = self.shell('check_dependencies() { :; }; fetch_osv() { echo "dir=${FEED_OUTPUT_DIR:-} args=$*"; }; '
                            "main --fetch-osv go")
        self.assertEqual(output.strip(), "dir= args=go")


class RuntimeRangeTests(AuditCase):
    def test_exclusions_and_version_lists_do_not_warn_about_other_lines(self):
        self.write(".nvmrc", "99\n")
        feed = self.feed("pkg:runtime/node@18.0.0 18.1.0 18.2.0?cve=CVE-2099-0001",
                         "pkg:runtime/node@>=98.0.0 !=99.* <100.0.0?cve=CVE-2099-0002")
        output = self.scan("--no-config", "--source", feed, code=0)
        self.assertNotIn("CVE-2099", output)


class LockfileWarningTests(AuditCase):
    def test_unreadable_lockfile_shape_is_reported(self):
        self.write("yarn.lock", "this is not a yarn lockfile\n")
        output = self.scan("--source", self.feed("pkg:npm/demo@1.5.0"), code=0)
        self.assertIn("No package could be read from this file", output)

    def test_go_mod_beside_go_sum_is_not_reported(self):
        self.write("go.mod", "module example.com/app\n\nrequire example.com/demo v1.0.0\n")
        self.write("go.sum", "example.com/demo v1.0.0 h1:abc=\n")
        output = self.scan("--source", self.feed("pkg:golang/example.com/other@1.0.0"), "--no-runtime-check", code=0)
        self.assertNotIn("No package could be read", output)


class GithubTests(AuditCase):
    def test_empty_organization_counts_zero_repositories(self):
        output = self.shell('''
            GITHUB_ORG=org; github_request() { echo '[]'; }
            get_github_repositories 2>&1''')
        self.assertIn("Total repositories found: 0", output)

    def test_empty_repository_is_skipped_without_error(self):
        output = self.shell('''
            github_request() {
                case "$1" in */branches/*) return 1 ;; *) echo '{"default_branch":"main","size":0}' ;; esac
            }
            search_package_json_in_repo_tree org/empty empty''')
        self.assertIn("Empty repository", output)

    def test_zero_size_repository_with_a_branch_is_still_scanned(self):
        # GitHub computes "size" asynchronously: a fresh repository reads 0.
        output = self.shell('''
            github_request() {
                case "$1" in
                    */branches/*) echo '{"commit":{"sha":"0123456789abcdef0123456789abcdef01234567"}}' ;;
                    */git/trees/*) echo '{"tree":[{"path":"package.json","type":"blob"}],"truncated":false}' ;;
                    *) echo '{"default_branch":"main","size":0}' ;;
                esac
            }
            curl() { printf '{"dependencies":{"demo":"1.5.0"}}'; }
            GITHUB_OUTPUT_DIR="$PWD/packages"
            search_package_json_in_repo_tree org/fresh fresh''')
        self.assertNotIn("Empty repository", output)
        self.assertTrue((self.root / "packages/fresh/package.json").exists())

    def test_unfetchable_repository_makes_a_clean_org_scan_incomplete(self):
        output = self.shell('''
            sleep() { :; }
            get_github_repositories() { printf 'broken|org/broken\\n'; }
            search_package_json_in_repo_tree() { return 1; }
            main --no-config --github-org org --github-token test-placeholder --source "$PWD/feed.purl" 2>&1
        '''.replace("$PWD/feed.purl", str(self.feed("pkg:npm/demo@1.5.0"))), code=3)
        self.assertIn("1 repository(ies) could not be fetched", output)

    def test_large_issue_body_is_sent_through_stdin(self):
        body = "x" * 300000
        self.write("body.txt", body)
        self.shell('''
            GITHUB_TOKEN=test-placeholder
            curl() {
                local arg
                for arg in "$@"; do [ ${#arg} -lt 100000 ] || { echo "argument too long" >&2; return 2; }; done
                cat > payload.json
                printf '{"html_url":"https://github.invalid/issue/1"}\\n201'
            }
            create_github_issue org/repo title "$(cat body.txt)"''')
        self.assertEqual(json.loads((self.root / "payload.json").read_text())["body"], body)
