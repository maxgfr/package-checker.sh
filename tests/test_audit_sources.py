"""Audit regressions in vulnerability sources and version comparison."""
import json

from test_audit import AuditCase


class SourceParserTests(AuditCase):
    def lookup(self, parser, document, *args):
        self.write("source.in", document)
        return self.shell(parser + " source.in " + " ".join(args))

    def test_sbom_parent_component_keeps_its_bom_ref(self):
        sbom = {"components": [{"bom-ref": "outer", "purl": "pkg:npm/outer@1.0.0",
                                "components": [{"bom-ref": "inner", "purl": "pkg:npm/inner@2.0.0"}]}],
                "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "outer"}, {"ref": "inner"}]}]}
        output = self.lookup("parse_sbom_to_lookup_eval", json.dumps(sbom, indent=2))
        self.assertIn("VULN_EXACT_LOOKUP['npm:outer']+='|1.0.0'", output)
        self.assertIn("VULN_EXACT_LOOKUP['npm:inner']+='|2.0.0'", output)

    def test_sbom_affects_keys_in_any_order_and_escaped_slashes(self):
        document = ('{"vulnerabilities":[{"id":"CVE-1","affects":['
                    '{"versions":[{"version":"1.0.1"}],"ref":"pkg:npm/a@1.0.0"},'
                    '{"ref":"pkg:composer\\/vendor\\/pkg@1.0.0"}]}]}')
        output = self.lookup("parse_sbom_to_lookup_eval", document)
        self.assertIn("VULN_EXACT_LOOKUP['npm:a']+='|1.0.0|1.0.1'", output)
        self.assertIn("VULN_EXACT_LOOKUP['composer:vendor/pkg']+='|1.0.0'", output)

    def test_json_source_scalar_versions_and_escaped_names(self):
        output = self.lookup("parse_json_to_lookup_eval",
                             '{"lodash": {"versions": "4.17.20"}, "@scope\\/pkg": {"versions": ["1.0.0"]}}')
        self.assertIn("VULN_EXACT_LOOKUP['*:lodash']+='|4.17.20'", output)
        self.assertIn("VULN_EXACT_LOOKUP['*:@scope/pkg']+='|1.0.0'", output)

    def test_csv_stray_quote_does_not_swallow_later_rows(self):
        output = self.lookup("parse_csv_to_lookup_eval",
                             'name,versions,description\nfoo,1.0.0,5" display\nlodash,4.17.20,x\n'
                             'express,4.0.0,"multi\nline"\n"a,b",">=1.0.0 <2.0.0",y\n')
        for key in ("*:foo", "*:lodash", "*:express"):
            self.assertIn("VULN_EXACT_LOOKUP['" + key + "']", output)
        self.assertIn("VULN_RANGE_LOOKUP['*:a,b']+='>=1.0.0 <2.0.0", output)

    def test_csv_missing_named_column_is_an_error(self):
        self.project()
        self.write("feed.csv", "id,package,affected\n1,demo,1.5.0\n")
        output = self.scan("--source", "feed.csv", "--csv-columns", "name,version", code=2)
        self.assertIn("Unable to parse", output)
        self.assertNotIn("SUMMARY", output)

    def test_csv_byte_order_mark_with_named_columns(self):
        self.project()
        (self.root / "feed.csv").write_bytes(b"\xef\xbb\xbfname,versions,severity\r\ndemo,1.5.0,high\r\n")
        self.assertIn("demo@1.5.0", self.scan("--source", "feed.csv", "--csv-columns", "name,versions"))

    def test_csv_unterminated_quote_is_an_error(self):
        self.project()
        self.write("feed.csv", 'name,versions\ndemo,"1.5.0\n')
        self.scan("--source", "feed.csv", code=2)

    def test_purl_type_case_subpath_and_query_encoding(self):
        output = self.lookup("parse_purl_to_lookup_eval",
                             "pkg:NPM/demo@1.5.0?severity=high&ghsa=GHSA-1;x&cve=CVE%2D2026%2D1&fixed=1.6.0#lib/x.js\n")
        self.assertIn("VULN_EXACT_LOOKUP['npm:demo']+='|1.5.0'", output)
        self.assertIn("VULN_RECORDS['npm:demo@1.5.0']+='high;GHSA-1,x;CVE-2026-1;;1.6.0;", output)


class RangeTests(AuditCase):
    CASES = [
        ("pypi", "1.0", "===1.0", True), ("pypi", "1.0.1", "===1.0", False),
        ("pypi", "1.0rc1", "==1.0.*", True), ("pypi", "1.0.5", "==1.0.*", True),
        ("pypi", "1.1rc1", "==1.0.*", False),
        ("pypi", "1.5", ">=1.0, !=1.3.*, <2.0", True), ("pypi", "1.3.2", ">=1.0, !=1.3.*, <2.0", False),
        ("pypi", "3.0rc1", "~=2.2", False), ("pypi", "2.9", "~=2.2", True),
        ("npm", "1.0.1", "1.0.0, 1.0.1", True), ("npm", "1.0.2", "1.0.0, 1.0.1", False),
        ("npm", "1.0.0", "1.0.0 1.0.1", True), ("npm", "1.5.0", "1.x", True), ("npm", "2.0.0", "1.x", False),
    ]

    def test_range_dialects(self):
        body = "".join('CHECK_ECO=%s; version_in_range "%s" "%s" && echo IN || echo out\n' % case[:3]
                       for case in self.CASES)
        results = self.shell(body).split()
        self.assertEqual(len(results), len(self.CASES))
        for case, result in zip(self.CASES, results):
            with self.subTest(case=case):
                self.assertEqual(result, "IN" if case[3] else "out")


class ComparatorTests(AuditCase):
    CASES = [
        ("pypi", "2023.18446744073709551617", "2023.2", "1"), ("pypi", "1!1.0", "2.0", "1"),
        ("gem", "1.18446744073709551617", "1.2", "1"),
        ("nuget", "1.18446744073709551617.0", "1.2.0", "1"), ("nuget", "1.0.0.1", "1.0.0", "1"),
        ("composer", "1.0.0-beta18446744073709551617", "1.0.0-beta2", "1"),
        ("composer", "1.0.0-preview", "1.0.0", "-1"), ("composer", "1.0.0-RC1-dev", "1.0.0-RC1", "-1"),
        ("composer", "1.0.0-beta.1.2", "1.0.0-beta.1.10", "-1"), ("composer", "1.0.0-p1", "1.0.0", "1"),
    ]

    def test_numeric_parts_of_any_length_and_stability_suffixes(self):
        body = "".join('compare_versions_eco %s "%s" "%s"; echo "$COMPARE_RESULT"\n' % case[:3] for case in self.CASES)
        results = self.shell(body).split()
        self.assertEqual(len(results), len(self.CASES))
        for case, result in zip(self.CASES, results):
            with self.subTest(case=case):
                self.assertEqual(result, case[3])

    def test_nuget_wildcard_is_not_expanded_against_the_directory(self):
        self.write("1.zzz", "")
        self.assertEqual(self.shell('compare_versions_nuget "1.*" "1.zzz"; echo "$COMPARE_RESULT"').strip(), "-1")
