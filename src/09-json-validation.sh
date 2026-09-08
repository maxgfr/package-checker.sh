# Syntax validation for JSON inputs; scan-time code must not require jq.
# Stream tokens through a small grammar stack. Repeated indexing into a growing
# whole-document string becomes quadratic with some awk implementations.
json_is_valid() {
    printf '%s\n' "$1" | LC_ALL=C awk '
    function take_value() {
        if (state[depth] != "value" && state[depth] != "value-or-end") return 0
        state[depth] = depth ? "comma-or-end" : "done"
        return 1
    }
    function finish_token() {
        if (token == "") return 1
        if (token !~ /^(true|false|null)$/ &&
            token !~ /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/) return 0
        token = ""
        return take_value()
    }
    function character(c) {
        if (quoted) {
            if (c ~ /[\001-\037]/) return 0
            if (unicode) {
                if (c !~ /^[0-9a-fA-F]$/) return 0
                unicode--
            } else if (escaped) {
                escaped = 0
                if (c == "u") unicode = 4
                else if (c !~ /^["\\\/bfnrt]$/) return 0
            } else if (c == "\\") escaped = 1
            else if (c == "\"") {
                quoted = 0
                if (key_string) state[depth] = "colon"
                else if (!take_value()) return 0
            }
            return 1
        }
        if (c !~ /^[ \t\r\n{}\[\],:"]$/) { token = token c; return 1 }
        if (!finish_token()) return 0
        if (c ~ /^[ \t\r\n]$/) return 1
        if (c == "\"") {
            key_string = (state[depth] == "key" || state[depth] == "key-or-end")
            if (!key_string && state[depth] != "value" && state[depth] != "value-or-end") return 0
            quoted = 1
        } else if (c == "{" || c == "[") {
            if (!take_value() || depth >= 128) return 0
            kind[++depth] = c
            state[depth] = c == "{" ? "key-or-end" : "value-or-end"
        } else if (c == "}" || c == "]") {
            if (!depth || (c == "}" && kind[depth] != "{") ||
                (c == "]" && kind[depth] != "[")) return 0
            if (state[depth] != "comma-or-end" && state[depth] != "key-or-end" &&
                state[depth] != "value-or-end") return 0
            depth--
        } else if (c == ":") {
            if (state[depth] != "colon") return 0
            state[depth] = "value"
        } else if (c == ",") {
            if (!depth || state[depth] != "comma-or-end") return 0
            state[depth] = kind[depth] == "{" ? "key" : "value"
        }
        return 1
    }
    BEGIN { depth = 0; state[0] = "value" }
    {
        # Most pretty-printed lockfile records contain short, unescaped tokens.
        # Consume whole strings/numbers there, keeping the bounded byte path for
        # escapes and long compact records. Both paths use the same grammar.
        if (length($0) < 4096 && $0 !~ /\\/) {
            rest = $0
            while (length(rest)) {
                if (match(rest, /^[ \t\r]+/)) {
                    rest = substr(rest, RLENGTH + 1)
                } else if (match(rest, /^"[^"\001-\037]*"/)) {
                    rest = substr(rest, RLENGTH + 1)
                    if (state[depth] == "key" || state[depth] == "key-or-end") state[depth] = "colon"
                    else if (!take_value()) { invalid = 1; exit }
                } else if (match(rest, /^[^ \t\r{}\[\],:"]+/)) {
                    token = substr(rest, 1, RLENGTH)
                    rest = substr(rest, RLENGTH + 1)
                    if (!finish_token()) { invalid = 1; exit }
                } else {
                    if (!character(substr(rest, 1, 1))) { invalid = 1; exit }
                    rest = substr(rest, 2)
                }
            }
            if (!character("\n")) { invalid = 1; exit }
            next
        }
        # Bound memory for compact single-line lockfiles as well.
        for (offset = 1; offset <= length($0); offset += 4096) {
            size = split(substr($0, offset, 4096), chars, "")
            for (i = 1; i <= size; i++) {
                if (!character(chars[i])) { invalid = 1; exit }
            }
        }
        if (!character("\n")) { invalid = 1; exit }
    }
    END { exit (invalid || quoted || depth || !finish_token() || state[0] != "done") }
    '
}
