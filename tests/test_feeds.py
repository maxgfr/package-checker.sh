import json
import subprocess
import unittest

from test_regressions import BASH, SCRIPT


class FeedTests(unittest.TestCase):
    def emit(self, events, versions=None, **fields):
        advisory = {"id": "GHSA-fixture", "database_specific": {"severity": "HIGH"}, "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "ranges": [{"type": "SEMVER", "events": events}], "versions": versions or []}], **fields}
        result = subprocess.run([BASH, "-c", 'source "$1"; jq -r --arg source ghsa --argjson ecomap \'{"npm":"npm"}\' "$FEED_JQ_PROGRAM"', "test", str(SCRIPT)], input=json.dumps(advisory), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_all_disjoint_intervals_are_emitted(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}, {"fixed": "4.0.0"}])
        self.assertEqual(len(lines), 2)
        self.assertIn("@>=1.0.0 <2.0.0?", lines[0])
        self.assertIn("@>=3.0.0 <4.0.0?", lines[1])

    def test_reintroduced_open_interval_does_not_reuse_previous_fix(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}])
        self.assertEqual(len(lines), 2)
        self.assertIn("@>=3.0.0?", lines[1])

    def test_withdrawn_advisories_are_excluded(self):
        self.assertEqual(self.emit([{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z"), [])

    def test_cvss_vector_does_not_drop_advisory(self):
        lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}], database_specific={}, severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        self.assertEqual(len(lines), 1)
        self.assertIn("@>=0 <2.0.0?", lines[0])

    def test_limit_bounds_do_not_become_open_intervals(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"limit": "2.0.0"}])
        self.assertEqual(len(lines), 1)
        self.assertIn("@>=1.0.0 <2.0.0?", lines[0])

    def test_limit_applies_to_every_interval_and_all_alternatives(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"fixed": "2.0.0"},
                           {"introduced": "3.0.0"}, {"limit": "3.5.0"}, {"limit": "4.0.0"}])
        self.assertEqual(len(lines), 4)
        for constraint in [">=1.0.0 <2.0.0 <3.5.0", ">=1.0.0 <2.0.0 <4.0.0",
                           ">=3.0.0 <3.5.0", ">=3.0.0 <4.0.0"]:
            self.assertTrue(any("@" + constraint + "?" in line for line in lines), lines)

    def test_explicit_versions_are_not_duplicated_alongside_ranges(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], versions=["1.0.0", "1.5.0"])
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("@>=1.0.0 <2.0.0?", lines[0])

    def test_explicit_versions_are_emitted_without_ranges(self):
        lines = self.emit([], versions=["1.0.0"], affected=[{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.0.0"]}])
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("@1.0.0?", lines[0])

    def test_affected_entry_without_package_is_skipped(self):
        lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}])
        advisory_lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}],
                                   affected=[{"package": {"ecosystem": "npm", "name": "demo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]},
                                             {"package": None, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}])
        self.assertEqual(advisory_lines, lines)


    def params(self, line):
        return dict(pair.split("=", 1) for pair in line.split("?", 1)[1].split("&"))

    def test_severity_is_computed_from_cvss_vector(self):
        for vector, expected in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
                                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "moderate"),
                                 ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "low")]:
            with self.subTest(vector=vector):
                lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}], database_specific={},
                                  severity=[{"type": "CVSS_V3", "score": vector}, {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}])
                self.assertEqual(len(lines), 1, lines)
                self.assertEqual(self.params(lines[0])["severity"], expected)

    def test_incomplete_cvss_vector_keeps_the_advisory(self):
        lines = self.emit([{"introduced": "0"}, {"fixed": "1.2"}], database_specific={},
                          severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}])
        self.assertEqual(len(lines), 1, lines)
        self.assertEqual(self.params(lines[0])["severity"], "unknown")

    def test_osv_copy_keeps_its_ghsa_id_and_other_ids(self):
        lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}], aliases=["CVE-2026-1"])
        self.assertEqual(self.params(lines[0])["ghsa"], "GHSA-fixture")
        lines = self.emit([{"introduced": "0"}, {"fixed": "2.0.0"}], id="PYSEC-2026-1", aliases=["GHSA-alias", "CVE-2026-1"])
        params = self.params(lines[0])
        self.assertEqual((params["ghsa"], params["cve"], params["id"]), ("GHSA-alias", "CVE-2026-1", "PYSEC-2026-1"))

    def test_malicious_packages_are_critical(self):
        lines = self.emit([], id="MAL-2026-1", database_specific={},
                          affected=[{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.0.0"]}])
        self.assertEqual(self.params(lines[0])["severity"], "critical")

    def test_open_interval_is_bounded_by_last_known_affected_range(self):
        affected = [{"package": {"ecosystem": "npm", "name": "demo"}, "database_specific": {"last_known_affected_version_range": "<= 2.26.11"},
                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]}]
        lines = self.emit([], affected=affected)
        self.assertEqual(len(lines), 1)
        self.assertIn("@>=2.0.0 <=2.26.11?", lines[0])
        self.assertEqual(self.params(lines[0])["fixed"], "")

    def test_scheme_is_stripped_from_action_and_swift_names(self):
        result = subprocess.run([BASH, "-c", 'source "$1"; jq -r --arg source osv --argjson ecomap \'{"SwiftURL":"swift","GitHub Actions":"githubactions"}\' "$FEED_JQ_PROGRAM"', "test", str(SCRIPT)],
                                input=json.dumps({"id": "GHSA-x", "affected": [
                                    {"package": {"ecosystem": "SwiftURL", "name": "ssh://github.com/Apple/Swift-NIO.git/"}, "versions": ["1.0.0"]},
                                    {"package": {"ecosystem": "GitHub Actions", "name": "https://github.com/Owner/Action"}, "versions": ["1.0.0"]}]}),
                                capture_output=True, text=True, timeout=10)
        self.assertIn("pkg:swift/github.com/apple/swift-nio@1.0.0", result.stdout)
        self.assertIn("pkg:githubactions/owner/action@1.0.0", result.stdout)

    def test_bitnami_runtime_advisory(self):
        advisory = {"id": "BIT-node-2026-111497", "aliases": ["BIT-node-min-2026-111497", "CVE-2026-111497"],
                    "database_specific": {"severity": "Critical"},
                    "affected": [{"package": {"ecosystem": "Bitnami", "name": "node"}, "ranges": [{"type": "SEMVER", "events": [
                        {"introduced": "0"}, {"fixed": "22.23.4"}, {"introduced": "23.0.0"}, {"fixed": "24.22.1"}]}]}]}
        result = subprocess.run([BASH, "-c", 'source "$1"; jq -r --arg source osv --argjson ecomap \'{"Bitnami":"runtime"}\' "$FEED_JQ_PROGRAM"', "test", str(SCRIPT)],
                                input=json.dumps(advisory), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.splitlines(), [
            "pkg:runtime/node@>=0 <22.23.4?severity=critical&cve=CVE-2026-111497&id=BIT-node-2026-111497&source=osv",
            "pkg:runtime/node@>=23.0.0 <24.22.1?severity=critical&cve=CVE-2026-111497&id=BIT-node-2026-111497&source=osv",
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
