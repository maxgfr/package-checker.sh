#!/usr/bin/env bash
# Build script: concatenates src/*.sh into the distributable script.sh
set -euo pipefail
cd "$(dirname "$0")"

OUT="script.sh"
TMP="$OUT.tmp"
trap 'rm -f "$TMP"' EXIT

# Deterministic file order (byte-wise sort, subdirs included)
FILES=$(find src -type f -name '*.sh' | LC_ALL=C sort)

# Preflight: every src file must end with a newline (cat-concat safety)
for f in $FILES; do
    if [ -n "$(tail -c1 "$f")" ]; then
        echo "ERROR: $f does not end with a newline" >&2; exit 1
    fi
done

: > "$TMP"
first=1
for f in $FILES; do
    if [ "$first" = 1 ]; then
        cat "$f" >> "$TMP"; first=0
    else
        # Strip a leading shebang if a contributor added one
        sed '1{/^#!/d;}' "$f" >> "$TMP"
    fi
done

# Sanity checks
bash -n "$TMP"
[ "$(grep -c '^#!' "$TMP")" = 1 ] || { echo "ERROR: multiple shebangs" >&2; exit 1; }
# The build must end with the `source`-guard block invoking main.
[ "$(tail -n1 "$TMP")" = 'fi' ] || { echo "ERROR: build does not end with the 'fi' of the run guard" >&2; exit 1; }
grep -qF 'main "$@"' "$TMP" || { echo "ERROR: 'main \"\$@\"' invocation missing" >&2; exit 1; }
grep -q '^VERSION="' "$TMP" || { echo "ERROR: VERSION line missing" >&2; exit 1; }

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --severity=error "$TMP"
fi

mv "$TMP" "$OUT"
chmod +x "$OUT"
trap - EXIT
echo "Built $OUT ($(wc -l < "$OUT" | tr -d ' ') lines)"
