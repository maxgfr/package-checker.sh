"""Audit regressions in feed generation (jq program, staging, CLI arguments)."""
import json
import stat
import zipfile

from test_audit import AuditCase


def advisory(adv_id, name="demo", ecosystem="npm", events=None, **extra):
    affected = {"package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "SEMVER", "events": events or [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
    affected.update(extra.pop("affected_extra", {}))
    return {"id": adv_id, "affected": [affected], **extra}


class FeedProgramTests(AuditCase):
    def emit(self, *documents, ecomap='{"npm":"npm","crates.io":"cargo"}', code=0):
        for index, document in enumerate(documents):
            text = document if isinstance(document, str) else json.dumps(document)
            self.write("in/%d.json" % index, text)
        self.shell("feed_emit_raw in osv '%s' out.purl" % ecomap, code=code)
        path = self.root / "out.purl"
        return sorted(path.read_text().splitlines()) if path.exists() else []

    def test_rustsec_informational_notices_are_not_vulnerabilities(self):
        notice = advisory("RUSTSEC-2021-0139", "ansi_term", "crates.io", [{"introduced": "0.0.0-0"}],
                          affected_extra={"database_specific": {"informational": "unmaintained"}})
        real = advisory("RUSTSEC-2021-0003", "smallvec", "crates.io",
                        affected_extra={"database_specific": {"informational": None}})
        lines = self.emit(notice, real)
        self.assertEqual([line.split("?")[0] for line in lines], ["pkg:cargo/smallvec@>=0 <2.0.0"])

    def test_malformed_fields_do_not_drop_the_advisory(self):
        document = advisory("GHSA-aaaa-bbbb-cccc", "demo", aliases=[None, "CVE-2026-1"],
                            database_specific={"severity": {"unexpected": "object"}})
        document["affected"].insert(0, {"package": {"ecosystem": "npm"}, "versions": ["1.0.0"]})
        lines = self.emit(document)
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith("pkg:npm/demo@>=0 <2.0.0?"))
        self.assertIn("cve=CVE-2026-1", lines[0])

    def test_repeated_introduced_keeps_the_earliest_bound(self):
        lines = self.emit(advisory("GHSA-x", events=[{"introduced": "0"}, {"introduced": "1.0.0"}, {"fixed": "2.0.0"}]))
        self.assertEqual([line.split("?")[0] for line in lines], ["pkg:npm/demo@>=0 <2.0.0"])

    def test_limit_only_ranges_fall_back_to_listed_versions(self):
        document = advisory("GHSA-y", events=[{"limit": "3.0.0"}])
        document["affected"][0]["versions"] = ["1.0.0", "1.1.0"]
        lines = self.emit(document)
        self.assertEqual([line.split("?")[0] for line in lines], ["pkg:npm/demo@1.0.0", "pkg:npm/demo@1.1.0"])

    def test_cvss_vector_without_scope_is_not_scored(self):
        document = advisory("OSV-1", severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"}])
        self.assertIn("severity=unknown", self.emit(document)[0])

    def test_one_broken_file_in_a_batch_keeps_the_others(self):
        lines = self.emit(advisory("GHSA-ok"), "{broken json")
        self.assertEqual(len(lines), 1)

    def test_empty_input_directory_is_an_error(self):
        (self.root / "in").mkdir()
        self.assertEqual(self.emit(code=1), [])


class FeedInstallTests(AuditCase):
    def fake_osv_zip(self, *documents):
        with zipfile.ZipFile(self.root / "all.zip", "w") as archive:
            for index, document in enumerate(documents):
                archive.writestr("%d.json" % index, json.dumps(document))

    CURL = 'curl() { while [ "$1" != -o ]; do shift; done; cp all.zip "$2"; }'

    def test_generated_feed_is_world_readable(self):
        self.fake_osv_zip(advisory("GHSA-ok"))
        self.shell('FEED_OUTPUT_DIR="$PWD/feeds"; ' + self.CURL + "; fetch_osv npm")
        mode = stat.S_IMODE((self.root / "feeds/osv.purl").stat().st_mode)
        self.assertEqual(mode, 0o644)

    def test_empty_generation_keeps_the_previous_feed(self):
        self.write("feeds/osv.purl", "previous feed\n")
        self.fake_osv_zip(advisory("GHSA-other", ecosystem="PyPI"))
        self.shell('FEED_OUTPUT_DIR="$PWD/feeds"; ' + self.CURL + "; fetch_osv npm", code=1)
        self.assertEqual((self.root / "feeds/osv.purl").read_text(), "previous feed\n")

    def test_fetch_aliases_and_unknown_ecosystems(self):
        output = self.shell('fetch_osv() { feed_resolve_types "$@" && echo "${FEED_TYPES[*]}"; }; fetch_osv go rust python go')
        self.assertEqual(output.strip(), "golang cargo pypi")
        self.shell("fetch_ghsa nonsense", code=1)
        self.shell("fetch_osv nonsense", code=1)

    def test_fetch_osv_accepts_an_existing_directory_name(self):
        (self.root / "data").mkdir()
        self.shell('check_dependencies() { :; }; fetch_osv() { printf "%s|%s" "$FEED_OUTPUT_DIR" "$*" > called; }; '
                   "main --fetch-osv data")
        self.assertEqual((self.root / "called").read_text(), "data|")
