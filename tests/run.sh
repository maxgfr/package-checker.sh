#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
# Feeds the script downloads go to a per-user cache: keep the suite's out of it.
feed_cache=$(mktemp -d)
trap 'rm -rf "$feed_cache"' EXIT
export PACKAGE_CHECKER_CACHE_DIR="$feed_cache/feeds"
cd "$(dirname "$0")/.."
for tool in jq python3 shellcheck; do
    command -v "$tool" >/dev/null || { echo "Test dependency missing: $tool" >&2; exit 1; }
done
bash -n script.sh
shellcheck --severity=error script.sh
bash tests/test-fixtures.sh
bash test-fixtures/test-feed-generation.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
