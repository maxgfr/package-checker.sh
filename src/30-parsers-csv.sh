# CSV source parser: generates lookup-table eval statements in a single awk
# pass. Handles quoted fields, multi-line quoted values, Windows line endings
# and version ranges. Args: FILE [COLUMNS], COLUMNS being "pkg,version" as
# 1-based indexes ("1,2") or header names ("name,versions").
#
# The first line is a header when columns are given by name, or when its
# version field does not look like a version or a range; a headerless file
# therefore keeps its first row.
parse_csv_to_lookup_eval() {
    local file="$1" columns="${2:-}"
    local col1="${columns%%,*}" col2=""
    [[ "$columns" == *,* ]] && col2="${columns#*,}" && col2="${col2%%,*}"
    col1="${col1#"${col1%%[![:space:]]*}"}"; col1="${col1%"${col1##*[![:space:]]}"}"
    col2="${col2#"${col2%%[![:space:]]*}"}"; col2="${col2%"${col2##*[![:space:]]}"}"

    tr -d '\r' < "$file" | awk -v col1="$col1" -v col2="$col2" "$AWK_FEED_LIB"'
    BEGIN {
        pkg_col = 1
        ver_col = 2
        by_name = (col1 != "" && col2 != "" && !(col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/))
        if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
            pkg_col = int(col1)
            ver_col = int(col2)
        }
    }

    function is_range(v) {
        return (v ~ /[><=,~^*]/ || index(v, "||") > 0)
    }

    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }

    function parse_csv_line(line, f,    i, n, in_quote, field, c) {
        n = 1
        field = ""
        in_quote = 0
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            if (c == "\"") {
                if (in_quote && substr(line, i+1, 1) == "\"") {
                    field = field "\""
                    i++
                } else {
                    in_quote = !in_quote
                }
            } else if (c == "," && !in_quote) {
                f[n] = trim(field)
                n++
                field = ""
            } else {
                field = field c
            }
        }
        f[n] = trim(field)
        return n
    }

    {
        if (pending_line != "") {
            current_line = pending_line " " $0
            pending_line = ""
        } else {
            current_line = $0
        }

        # An odd number of quotes means the quoted field continues.
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            pending_line = current_line
            next
        }

        if (current_line == "") next

        field_count = parse_csv_line(current_line, fields)

        if (!header_checked) {
            header_checked = 1
            if (by_name) {
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    if (lower_field == tolower(col1)) pkg_col = i
                    if (lower_field == tolower(col2)) ver_col = i
                }
                next
            }
            if (fields[ver_col] !~ /^([<>=~^*]|[vV]?[0-9])/) next
        }

        pkg = fields[pkg_col]
        ver = fields[ver_col]
        if (pkg == "" || ver == "") next

        # CSV carries no ecosystem info -> wildcard namespace "*:"
        add_entry("*:" pkg, ver, "", is_range(ver))
    }

    END { emit_lookup() }
    '
}
