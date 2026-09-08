#!/usr/bin/env bash
# Build and exercise shipped images locally; no registry push or network scan.
set -euo pipefail
cd "$(dirname "$0")/.."
for variant in lite full all; do
    dockerfile=Dockerfile
    ecosystems=npm
    [ "$variant" != lite ] || dockerfile=Dockerfile.lite
    [ "$variant" != all ] || ecosystems=all
    image="checker:validation-$variant"
    docker build --load -f "$dockerfile" --build-arg "FEED_ECOSYSTEMS=$ecosystems" -t "$image" .
    docker run --rm --entrypoint sh "$image" -c '! command -v jq'
    status=0
    output=$(docker run --rm -v "$PWD/test-fixtures:/fixtures:ro" "$image" /fixtures/npm-project --source /fixtures/test-vulnerabilities.json) || status=$?
    test "$status" -eq 1
    [[ "$output" == *next@16.0.3* ]]
    docker run --rm -v "$PWD/test-fixtures:/fixtures:ro" "$image" /fixtures/safe-project --source /fixtures/test-vulnerabilities.json
    docker run --rm -e "VARIANT=$variant" --entrypoint sh "$image" -c '
        case "$VARIANT" in
            lite) test ! -d /app/data ;;
            full) test -f /app/data/ghsa.purl && test -f /app/data/osv.purl && test ! -f /app/data/ghsa-cargo.purl ;;
            all)
                for eco in pypi golang cargo gem composer maven nuget pub hex swift githubactions; do
                    test -f "/app/data/ghsa-$eco.purl" && test -f "/app/data/osv-$eco.purl" || exit 1
                done ;;
        esac'
    printf 'PASS: Docker %s\n' "$variant"
done
