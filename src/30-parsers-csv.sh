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

    function meta(name) {
        return (name in meta_col) ? fields[meta_col[name]] : ""
    }

    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }

    # RFC 4180: a quote opens a quoted field only at the start of a field
    # (after optional spaces); elsewhere it is a literal character, so a stray
    # quote such as 5" in a description cannot swallow the rest of the file.
    function parse_csv_line(line, f,    i, n, in_quote, field, c, at_start) {
        n = 1
        field = ""
        in_quote = 0
        at_start = 1
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            if (in_quote) {
                if (c == "\"") {
                    if (substr(line, i+1, 1) == "\"") { field = field "\""; i++ }
                    else in_quote = 0
                } else field = field c
            } else if (c == "\"" && at_start) {
                in_quote = 1
                at_start = 0
            } else if (c == ",") {
                f[n] = trim(field)
                n++
                field = ""
                at_start = 1
            } else {
                field = field c
                if (c !~ /[[:space:]]/) at_start = 0
            }
        }
        f[n] = trim(field)
        QUOTE_OPEN = in_quote
        return n
    }

    {
        if (pending_line != "") {
            current_line = pending_line " " $0
            pending_line = ""
        } else {
            current_line = $0
        }

        if (current_line == "") next

        # A quoted field still open at the end of the line continues on the next.
        field_count = parse_csv_line(current_line, fields)
        if (QUOTE_OPEN) {
            pending_line = current_line
            next
        }

        if (!header_checked) {
            header_checked = 1
            if (by_name || (fields[ver_col] !~ /^([<>=~^*(]|[vV]?[0-9])/ && substr(fields[ver_col], 1, 1) != "[")) {
                # Header row: locate the named columns, including the
                # optional advisory metadata (severity, ghsa, cve, source).
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    if (by_name && lower_field == tolower(col1)) pkg_col = i
                    if (by_name && lower_field == tolower(col2)) ver_col = i
                    if (lower_field ~ /^(severity|ghsa|cve|source)$/) { meta_col[lower_field] = i; has_meta = 1 }
                    if (lower_field == tolower(col1)) found1 = 1
                    if (lower_field == tolower(col2)) found2 = 1
                }
                # Named columns that the header lacks would silently load
                # other columns as package names and versions.
                if (by_name && !(found1 && found2)) {
                    printf "Error: CSV header has no column named %s\n", (found1 ? col2 : col1) > "/dev/stderr"
                    failed = 1
                    exit 1
                }
                next
            }
        }

        pkg = fields[pkg_col]
        ver = fields[ver_col]
        if (pkg == "" || ver == "") next

        record = ""
        if (has_meta) {
            ranged = range_like(ver)
            record = tolower(meta("severity")) ";" meta("ghsa") ";" meta("cve") ";" meta("source") ";" (ranged ? range_fix(ver) : "") ";"
        }
        # CSV carries no ecosystem info -> wildcard namespace "*:"
        add_entry("*:" loose_name(pkg), ver, record, range_like(ver))
    }

    END {
        if (failed) exit 1
        if (pending_line != "") {
            print "Error: unterminated quoted field in CSV source" > "/dev/stderr"
            exit 1
        }
        emit_lookup()
    }
    '
}
