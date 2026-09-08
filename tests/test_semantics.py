"""Regression oracles for pip logical lines and ecosystem version boundaries."""
import json
import random
import subprocess

from test_regressions import BASH, SCRIPT, CheckerCase


class SemanticsTests(CheckerCase):
    def test_json_grammar_against_seeded_standard_parser(self):
        rng = random.Random(1808)
        values = [None, True, False, 0, -1.25, "escaped\\\"\n", "é", [], {}]
        documents = []
        for _ in range(35):
            value = {"key": rng.choices(values, k=4), "nested": {"x": rng.choice(values)}}
            document = json.dumps(value, ensure_ascii=rng.choice([True, False]), indent=rng.choice([None, 2]))
            documents += [document, document[:-1], document + "false", document.replace(":", ",", 1)]
        documents += ['"' + "a" * 4095 + '\\u0041"', '[' * 128 + ']' * 128,
                      '{"x":true false}', '{"x":[]:2}', '[1,]', '{"a",1}', '"\\u00xz"']
        for document in documents:
            with self.subTest(document=document[:80]):
                try:
                    json.loads(document)
                    expected = 0
                except ValueError:
                    expected = 1
                result = subprocess.run([BASH, "-c", 'source "$1"; json_is_valid "$(<"$2")"',
                                         "test", str(SCRIPT), str(self.write("input.json", document))],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_requirements_hash_continuations(self):
        feed = self.feed("pkg:pypi/django@3.2?ghsa=GHSA-pin")
        for requirement in [
            "Django==3.2\n",
            "Django==3.2 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n",
            "Django[extra] == 3.\\\n2 --hash=sha256:abc # pinned\n",
            "Django==3.2 \\\r\n    --hash=sha256:abc\r\n",
        ]:
            with self.subTest(requirement=requirement):
                self.write("requirements.txt", requirement)
                self.assertIn("django@3.2", self.scan("--source", feed))

    def test_go_prerelease_boundaries(self):
        self.write("go.mod", "module example.com/app\n\nrequire example.com/demo v1.0.0-rc.1\n")
        for constraint, code in [(">=1.0.0 <2.0.0", 0), ("1.0.0", 0),
                                 (">=1.0.0-rc.1 <1.0.0", 1)]:
            with self.subTest(constraint=constraint):
                feed = self.feed("pkg:golang/example.com/demo@" + constraint)
                self.scan("--source", feed, code=code)

    def test_semver_or_branches_expand_independently(self):
        feed = self.feed("pkg:npm/demo@^1.0.0 || ^3.0.0")
        for version, code in [("1.5.0", 1), ("2.5.0", 0), ("3.5.0", 1), ("4.0.0", 0)]:
            with self.subTest(version=version):
                self.project(version)
                self.scan("--source", feed, code=code)

    def test_semver_large_numeric_identifiers(self):
        result = subprocess.run([BASH, "-c", '''source "$1"
compare_versions 1.0.0-999999999999999999999 1.0.0-1000000000000000000000
printf '%s' "$COMPARE_RESULT"
''', "bash", str(SCRIPT)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.stdout, "-1", result.stderr)
        self.assertEqual(result.stderr, "")
