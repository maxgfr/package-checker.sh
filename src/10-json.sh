# ============================================================================
# Minimal JSON accessors (awk, no jq dependency)
# For configuration files, package.json / composer files and GitHub API answers.
# ============================================================================

# One scanner for every accessor, fed with json_structural_lines records (one
# member per record, an opening { or [ at the end of its record, a closing }
# or ] alone): layout, escapes and document size are handled there.
#   mode=value  print the raw value of the top-level KEY of the root object
#   mode=items  print each element of the root array on its own line
# Only members of the root are considered, so a key name that appears as a
# string value or inside a nested object is never mistaken for the key.
AWK_JSON_SCAN='
function trim(t) {
    sub(/^[[:space:]]+/, "", t)
    sub(/[[:space:]]+$/, "", t)
    return t
}
# Split a member record into M_KEY ("" and M_HAS_KEY=0 for an array element)
# and M_VAL, the rest of the record.
function member(rec,   i, c, n, rest) {
    M_KEY = ""; M_VAL = rec; M_HAS_KEY = 0
    if (substr(rec, 1, 1) != "\"") return
    n = length(rec)
    for (i = 2; i <= n; i++) {
        c = substr(rec, i, 1)
        if (c == "\\") i++
        else if (c == "\"") break
    }
    rest = trim(substr(rec, i + 1))
    if (substr(rest, 1, 1) != ":") return
    M_HAS_KEY = 1
    M_KEY = substr(rec, 2, i - 2)
    M_VAL = trim(substr(rest, 2))
}
{
    rec = trim($0)
    if (rec == "") next
    closing = (rec == "}" || rec == "]")
    last = substr(rec, length(rec))
    opening = (!closing && (last == "{" || last == "["))
    if (capturing) {
        # Rebuild the nested value, restoring the commas between members.
        if (closing) {
            out = out rec
            if (--cdepth == 0) {
                print out
                capturing = 0
                if (mode == "value") exit
            }
            next
        }
        out = out (count[cdepth]++ ? "," : "") rec
        if (opening) count[++cdepth] = 0
        next
    }
    if (closing) { depth--; next }
    if (depth == 0) {
        if (rec != (mode == "value" ? "{" : "[")) exit
        depth = 1
        next
    }
    if (depth == 1) {
        member(rec)
        if (mode == "value") {
            wanted = (M_HAS_KEY && M_KEY == key)
            if (opening && wanted) { capturing = 1; out = M_VAL; cdepth = 1; count[1] = 0 }
            else if (opening) depth++
            else if (wanted) { print M_VAL; exit }
        } else if (opening) {
            capturing = 1; out = rec; cdepth = 1; count[1] = 0
        } else {
            print rec
        }
        next
    }
    if (opening) depth++
}
'

# Raw JSON value of a top-level key ("" when the key is absent).
# Usage: json_get_raw "$json" "key"
json_get_raw() {
    printf '%s\n' "$1" | json_structural_lines - | awk -v mode=value -v key="$2" "$AWK_JSON_SCAN"
}

# Scalar value of a top-level key: a string without its quotes (\" \/ and \\
# unescaped), or a number / true / false / null as written. Objects, arrays
# and absent keys print nothing.
# Usage: json_get_value "$json" "key"
json_get_value() {
    local raw
    raw=$(json_get_raw "$1" "$2")
    case "$raw" in
        '"'*'"')
            raw="${raw#\"}"; raw="${raw%\"}"
            raw="${raw//\\\//\/}"
            raw="${raw//\\\"/\"}"
            raw="${raw//\\\\/\\}"
            printf '%s\n' "$raw" ;;
        ''|'{'*|'['*) ;;
        *) printf '%s\n' "$raw" ;;
    esac
}

# Object (or array) value of a top-level key; "{}" when absent or scalar.
# Usage: json_get_object "$json" "key"
json_get_object() {
    local raw
    raw=$(json_get_raw "$1" "$2")
    case "$raw" in
        '{'*|'['*) printf '%s\n' "$raw" ;;
        *) echo "{}" ;;
    esac
}

# Array value of a top-level key; "[]" when absent.
# Usage: json_get_array "$json" "key"
json_get_array() {
    local result
    result=$(json_get_object "$1" "$2")
    [ "$result" != "{}" ] || result="[]"
    printf '%s\n' "$result"
}

# Elements of a JSON array, one per line (raw JSON).
# Usage: json_array_items "$json_array"
json_array_items() {
    printf '%s\n' "$1" | json_structural_lines - | awk -v mode=items "$AWK_JSON_SCAN"
}

# Non-empty string elements of a JSON array, unquoted, into JSON_STRINGS.
# Usage: json_read_strings "$json_array"
json_read_strings() {
    JSON_STRINGS=()
    local item
    while IFS= read -r item; do
        case "$item" in
            '"'*'"') item="${item#\"}"; item="${item%\"}" ;;
        esac
        [ -z "$item" ] || JSON_STRINGS+=("$item")
    done < <(json_array_items "$1")
}
