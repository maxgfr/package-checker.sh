# Put structural JSON delimiters on separate records without changing strings.
# Line-oriented lockfile readers can then handle compact or pretty JSON alike.
json_structural_lines() {
    awk '
    function flush() {
        if (buffer ~ /[^[:space:]]/) print buffer
        buffer = ""
    }
    {
        # Generated pretty JSON normally has one unescaped scalar per line.
        # Preserve the existing record whitespace while skipping its byte loop.
        if (!quoted && buffer !~ /[^[:space:]]/ &&
            $0 ~ /^[[:space:]]*"[^"\\]*"[[:space:]]*:[[:space:]]*("[^"\\]*"|true|false|null|-?[0-9.]+),?$/) {
            buffer = buffer $0
            if (substr(buffer, length(buffer), 1) == ",") {
                buffer = substr(buffer, 1, length(buffer) - 1)
                flush()
            }
            buffer = buffer " "
            next
        }
        # BSD awk scans to substr offsets in multibyte records. Bound the
        # inner offsets even when the entire lockfile occupies one long line.
        record_size = length($0)
        for (offset = 1; offset <= record_size; offset += 4096) {
            chunk = substr($0, offset, 4096)
            chunk_size = length(chunk)
            for (i = 1; i <= chunk_size; i++) {
                c = substr(chunk, i, 1)
            if (quoted) {
                buffer = buffer c
                if (escaped) escaped = 0
                else if (c == "\\") escaped = 1
                else if (c == "\"") quoted = 0
            } else if (c == "\"") {
                quoted = 1
                buffer = buffer c
            } else if (c == "{" || c == "[") {
                buffer = buffer c
                flush()
            } else if (c == "}" || c == "]") {
                flush()
                print c
            } else if (c == ",") {
                flush()
            } else {
                buffer = buffer c
            }
            }
        }
        if (!quoted) buffer = buffer " "
    }
    END { flush() }
    ' "$1"
}
