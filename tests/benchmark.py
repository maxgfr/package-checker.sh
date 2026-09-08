"""Repeatable offline benchmarks; accepts two distributables for comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scripts", nargs="+", type=Path)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="checker-bench-") as directory:
        work = Path(directory)
        project = work / "monorepo"
        for index in range(100):
            package = project / str(index)
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20", "express": "4.16.0"}}))
        fixtures = ROOT / "test-fixtures"
        large_lock = work / "large-lock"
        large_lock.mkdir()
        locked = {"node_modules/lodash": {"version": "4.17.20"}}
        locked.update({f"node_modules/unlisted-{index}": {"version": "1.0.0"}
                       for index in range(5000)})
        (large_lock / "package-lock.json").write_text(json.dumps(
            {"lockfileVersion": 3, "packages": locked}, indent=2))
        scenarios = {
            "small": (fixtures / "npm-project", fixtures / "test-vulnerabilities.json"),
            "polyglot": (fixtures / "polyglot-project", fixtures / "test-vulnerabilities-multi.purl"),
            "large-feed": (fixtures / "npm-project", fixtures / "test-vulnerabilities-huge.purl"),
            "monorepo": (project, fixtures / "test-vulnerabilities-huge.purl"),
            "large-lock": (large_lock, fixtures / "test-vulnerabilities-huge.purl"),
        }
        scripts = [script.resolve() for script in args.scripts]
        for name, (target, feed) in scenarios.items():
            samples = {script: {"durations": [], "memory": [], "hashes": set()} for script in scripts}
            for iteration in range(args.runs + 1):
                # Pair old/new measurements and alternate ordering to reduce
                # bias from changing background load on the developer machine.
                for script in scripts if iteration % 2 == 0 else reversed(scripts):
                    report = work / "report.json"
                    report.unlink(missing_ok=True)
                    command = [os.environ.get("TEST_BASH", "bash"), str(script), str(target), "--no-config", "--source", str(feed), "--export-json", str(report)]
                    timer = ["/usr/bin/time", "-l" if os.uname().sysname == "Darwin" else "-v"]
                    start = time.perf_counter()
                    result = subprocess.run(timer + command, text=True, capture_output=True, cwd=ROOT, env={**os.environ, "LC_ALL": "C"}, timeout=180)
                    elapsed = time.perf_counter() - start
                    if result.returncode != 1 or not report.exists():
                        raise RuntimeError(result.stdout + result.stderr)
                    parsed = json.loads(report.read_text())
                    canonical = json.dumps(parsed, sort_keys=True).replace(str(work), "<benchmark>")
                    sample = samples[script]
                    sample["hashes"].add(hashlib.sha256(canonical.encode()).hexdigest())
                    sample["report"] = parsed
                    match = re.search(r"(\d+)\s+maximum resident set size", result.stderr) or re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", result.stderr)
                    if iteration:
                        sample["durations"].append(elapsed)
                        sample["memory"].append(int(match[1]) * (1 if os.uname().sysname == "Darwin" else 1024))
            reference = samples[scripts[0]]
            for script in scripts:
                sample = samples[script]
                changes = []
                before, after = reference["report"], sample["report"]
                if before != after:
                    changes = [{"before": old, "after": new} for old, new in zip(before["vulnerabilities"], after["vulnerabilities"]) if old != new]
                    if len(before["vulnerabilities"]) != len(after["vulnerabilities"]):
                        changes.append({"occurrences_before": len(before["vulnerabilities"]), "occurrences_after": len(after["vulnerabilities"])})
                ratios = [old / new for old, new in zip(reference["durations"], sample["durations"])]
                print(json.dumps({"script": str(script), "scenario": name, "median_seconds": round(statistics.median(sample["durations"]), 4), "paired_speedup": round(statistics.median(ratios), 2), "max_rss_bytes": max(sample["memory"]), "report_hashes": sorted(sample["hashes"]), "report_changes": changes}), flush=True)



if __name__ == "__main__":
    main()
