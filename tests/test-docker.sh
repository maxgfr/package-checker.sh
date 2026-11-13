#!/usr/bin/env bash
# Build and exercise shipped images locally; no registry push or network scan.
# Usage: bash tests/test-docker.sh [lite|full|all|npm ...]  (default: all four)
# CI runs it once per variant (.github/workflows/test.yml).
set -euo pipefail
cd "$(dirname "$0")/.."
variants=("$@")
[ ${#variants[@]} -gt 0 ] || variants=(lite full all npm)
for variant in "${variants[@]}"; do
    dockerfile=Dockerfile
    build_args=()
    # "full" builds with no build-arg to exercise the Dockerfile's own default.
    case "$variant" in
        lite) dockerfile=Dockerfile.lite ;;
        all|npm) build_args=(--build-arg "FEED_ECOSYSTEMS=$variant") ;;
        full) ;;
        *) echo "Unknown variant: $variant" >&2; exit 2 ;;
    esac
    image="checker:validation-$variant"
    docker build --load -f "$dockerfile" ${build_args[@]+"${build_args[@]}"} -t "$image" .
    docker run --rm --entrypoint sh "$image" -c '! command -v jq'
    status=0
    output=$(docker run --rm -v "$PWD/test-fixtures:/fixtures:ro" "$image" /fixtures/npm-project --source /fixtures/test-vulnerabilities.json) || status=$?
    test "$status" -eq 1
    [[ "$output" == *next@16.0.3* ]]
    docker run --rm -v "$PWD/test-fixtures:/fixtures:ro" "$image" /fixtures/safe-project --source /fixtures/test-vulnerabilities.json
    docker run --rm -e "VARIANT=$variant" --entrypoint sh "$image" -c '
        case "$VARIANT" in
            lite) test ! -d /app/data ;;
            npm) test -f /app/data/ghsa.purl && test -f /app/data/osv.purl && test -f /app/data/osv-runtime.purl && test ! -f /app/data/ghsa-cargo.purl ;;
            full|all)
                test -f /app/data/ghsa.purl && test -f /app/data/osv.purl && test -f /app/data/osv-runtime.purl || exit 1
                for eco in pypi golang cargo gem composer maven nuget pub hex swift githubactions; do
                    test -f "/app/data/ghsa-$eco.purl" && test -f "/app/data/osv-$eco.purl" || exit 1
                done ;;
        esac'
    # The AI guides are bundled: --help-ai works without a network.
    output=$(docker run --rm --network none "$image" --help-ai prompt)
    [[ "$output" == *"AI System Prompt"* ]]
    if [ "$variant" != lite ]; then
        # The package-checker link finds the bundled feeds, offline.
        status=0
        output=$(docker run --rm --network none -v "$PWD/test-fixtures:/fixtures:ro" --entrypoint package-checker \
            "$image" /fixtures/npm-project --no-config 2>&1) || status=$?
        test "$status" -eq 1
        [[ "$output" == *"Using GHSA source: /app/data/ghsa.purl"* ]]
        # Baked-in feeds, however old, are not downloaded again by a new
        # container (curl replaced by a stub that records any call).
        docker run --rm -v "$PWD/test-fixtures:/fixtures:ro" --entrypoint sh "$image" -c '
            for f in /app/data/*.purl; do
                sed -i -e "/^# generated: /d" -e "1i # generated: 2020-01-01T00:00:00Z" "$f"
                touch -t 202001010000 "$f"
            done
            printf "#!/bin/sh\necho \"\$*\" >> /tmp/curl.log\nexit 7\n" > /usr/local/bin/curl
            chmod +x /usr/local/bin/curl
            status=0
            output=$(package-checker /fixtures/npm-project --no-config 2>&1) || status=$?
            test "$status" -eq 1 && test ! -e /tmp/curl.log || { echo "$output"; cat /tmp/curl.log; exit 1; }
            case "$output" in *"Using GHSA source: /app/data/ghsa.purl"*) ;; *) echo "$output"; exit 1 ;; esac'
    fi
    printf 'PASS: Docker %s\n' "$variant"
done
