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

    def test_explicit_versions_are_retained_alongside_ranges(self):
        lines = self.emit([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], versions=["3.0.0"])
        self.assertTrue(any("@3.0.0?" in line for line in lines), lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
