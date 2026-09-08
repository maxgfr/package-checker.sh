"""Exercise the release workflow's shell with a stub publisher and an old tag."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowTests(unittest.TestCase):
    def run_release(self, outcome):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Semantic Release\n", 1)[1]
        block = step.split("        run: |\n", 1)[1].split("\n  docker-release:", 1)[0]
        script = textwrap.dedent(block)
        config = json.loads((ROOT / ".releaserc.json").read_text())
        options = next(
            p[1] for p in config["plugins"]
            if isinstance(p, list) and p[0] == "@semantic-release/exec"
        )
        hook = options.get("successCmd", "true").replace("${nextRelease.version}", "1.11.55")
        with tempfile.TemporaryDirectory(prefix="release-test-") as directory:
            cwd = Path(directory)
            commands = [
                ["init", "-q"],
                ["-c", "commit.gpgsign=false", "-c", "user.name=Test",
                 "-c", "user.email=test@example.com", "commit", "--allow-empty",
                 "-qm", "fix: example"],
                ["-c", "tag.gpgsign=false", "tag", "v1.11.54"],
            ]
            for args in commands:
                subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)
            stub = cwd / "npx"
            stub.write_text('#!/bin/sh\ncase "$RELEASE_OUTCOME" in\nerror) echo "changelog generation failed" >&2; exit 23 ;;\npublished) exec sh -c "$SUCCESS_HOOK" ;;\nnone) exit 0 ;;\nesac\n')
            stub.chmod(0o755)
            output = cwd / "output"
            output.touch()
            env = {
                **os.environ, "PATH": f"{cwd}:{os.environ['PATH']}",
                "GITHUB_OUTPUT": str(output), "RELEASE_OUTCOME": outcome,
                "SUCCESS_HOOK": hook,
            }
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                cwd=cwd, env=env, text=True, capture_output=True, timeout=10,
            )
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            return result, outputs

    def test_failure_fails_workflow_without_publishing_old_version(self):
        result, outputs = self.run_release("error")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertNotEqual(outputs.get("new_release_published"), "true")
        self.assertNotIn("new_release_version", outputs)

    def test_no_release_does_not_republish_existing_tag(self):
        result, outputs = self.run_release("none")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs.get("new_release_published"), "false")
        self.assertNotIn("new_release_version", outputs)

    def test_success_reports_the_published_version(self):
        result, outputs = self.run_release("published")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs.get("new_release_published"), "true")
        self.assertEqual(outputs.get("new_release_version"), "1.11.55")


if __name__ == "__main__":
    unittest.main()
