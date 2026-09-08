#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
cd "$(dirname "$0")/.."
for tool in jq python3 shellcheck; do
    command -v "$tool" >/dev/null || { echo "Test dependency missing: $tool" >&2; exit 1; }
done
bash -n script.sh
shellcheck --severity=error script.sh
bash tests/test-fixtures.sh
bash test-fixtures/test-feed-generation.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
