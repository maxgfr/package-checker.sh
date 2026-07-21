is_version_range() {
    local version="$1"
    if [[ "$version" =~ (>=|<=|>|<) ]]; then
        return 0  # true - it's a range
    fi
    return 1  # false - it's an exact version
}

# FAST CSV Parser using awk - parses entire CSV in a single pass
# Handles: quoted fields, multi-line values, Windows line endings, version ranges
# Output: JSON object with versions and versions_range arrays
parse_csv_to_json() {
    local csv_data="$1"
    local col1="${CSV_COLUMNS[0]:-}"
    local col2="${CSV_COLUMNS[1]:-}"
    
    # Use awk for fast single-pass parsing
    echo "$csv_data" | tr -d '\r' | awk -v col1="$col1" -v col2="$col2" '
    BEGIN {
        FS = ","
        pkg_col = 1
        ver_col = 2
        header_done = 0
        pkg_count = 0
    }
    
    # Function to check if a string is a version range
    function is_range(v) {
        return (v ~ />/ || v ~ /</)
    }
    
    # Function to trim whitespace and quotes
    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }
    
    # Function to parse a CSV line handling quoted fields
    # Returns fields in array f[], returns field count
    function parse_csv_line(line, f,    i, j, n, in_quote, field, c) {
        n = 1
        field = ""
        in_quote = 0
        
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            
            if (c == "\"") {
                # Check for escaped quote (double quote)
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
        # Last field
        f[n] = trim(field)
        return n
    }
    
    # Handle multi-line quoted values by accumulating lines
    {
        # Accumulate line if we are in the middle of a quoted field
        if (pending_line != "") {
            current_line = pending_line " " $0
            pending_line = ""
        } else {
            current_line = $0
        }
        
        # Count quotes to check if line is complete
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            # Odd number of quotes - line continues
            pending_line = current_line
            next
        }
        
        # Skip empty lines
        if (current_line == "") next
        
        # Parse the line
        field_count = parse_csv_line(current_line, fields)
        
        # First non-empty line is header
        if (!header_done) {
            header_done = 1
            
            # Try to find column indices from header names if column names specified
            if (col1 != "" && col2 != "") {
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    lower_col1 = tolower(col1)
                    lower_col2 = tolower(col2)
                    
                    if (lower_field == lower_col1) pkg_col = i
                    if (lower_field == lower_col2) ver_col = i
                }
            } else if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
                # Numeric column indices
                pkg_col = int(col1)
                ver_col = int(col2)
            }
            
            # Skip header row
            next
        }
        
        # Extract package and version
        pkg = fields[pkg_col]
        ver = fields[ver_col]
        
        # Skip invalid entries
        if (pkg == "" || ver == "") next
        if (tolower(pkg) == "package" || tolower(pkg) == "name") next
        
        # Track package order (first occurrence)
        if (!(pkg in pkg_seen)) {
            pkg_seen[pkg] = 1
            pkg_order[++pkg_count] = pkg
        }
        
        # Categorize as version or range
        if (is_range(ver)) {
            if (pkg in pkg_ranges) {
                pkg_ranges[pkg] = pkg_ranges[pkg] ",\"" ver "\""
            } else {
                pkg_ranges[pkg] = "\"" ver "\""
            }
        } else {
            if (pkg in pkg_versions) {
                pkg_versions[pkg] = pkg_versions[pkg] ",\"" ver "\""
            } else {
                pkg_versions[pkg] = "\"" ver "\""
            }
        }
    }
    
    END {
        # Build JSON output
        printf "{"
        first = 1
        
        for (i = 1; i <= pkg_count; i++) {
            pkg = pkg_order[i]
            
            if (!first) printf ","
            first = 0
            
            printf "\"%s\":{", pkg
            has_content = 0
            
            if (pkg in pkg_versions) {
                printf "\"versions\":[%s]", pkg_versions[pkg]
                has_content = 1
            }
            
            if (pkg in pkg_ranges) {
                if (has_content) printf ","
                printf "\"versions_range\":[%s]", pkg_ranges[pkg]
            }
            
            printf "}"
        }
        
        printf "}"
    }
    '
}

# FAST CSV Parser that generates lookup table eval commands directly
# This bypasses the slow JSON intermediate step for large CSV files
# Returns: bash eval commands to populate VULN_EXACT_LOOKUP and VULN_RANGE_LOOKUP
parse_csv_to_lookup_eval() {
    local csv_data="$1"
    local col1="${CSV_COLUMNS[0]:-}"
    local col2="${CSV_COLUMNS[1]:-}"
    
    # Use awk to parse CSV and generate eval commands directly
    echo "$csv_data" | tr -d '\r' | awk -v col1="$col1" -v col2="$col2" '
    BEGIN {
        FS = ","
        pkg_col = 1
        ver_col = 2
        header_done = 0
        pkg_count = 0
    }
    
    function is_range(v) {
        return (v ~ />/ || v ~ /</)
    }
    
    function trim(s) {
        gsub(/^[[:space:]"]+/, "", s)
        gsub(/[[:space:]"]+$/, "", s)
        return s
    }
    
    function escape_sq(s) {
        gsub(/'\''/, "'\''\\'\'''\''", s)
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
        
        quote_count = gsub(/"/, "\"", current_line)
        if (quote_count % 2 == 1) {
            pending_line = current_line
            next
        }
        
        if (current_line == "") next
        
        field_count = parse_csv_line(current_line, fields)
        
        if (!header_done) {
            header_done = 1
            
            if (col1 != "" && col2 != "") {
                for (i = 1; i <= field_count; i++) {
                    lower_field = tolower(fields[i])
                    if (lower_field == tolower(col1)) pkg_col = i
                    if (lower_field == tolower(col2)) ver_col = i
                }
            } else if (col1 ~ /^[0-9]+$/ && col2 ~ /^[0-9]+$/) {
                pkg_col = int(col1)
                ver_col = int(col2)
            }
            next
        }
        
        pkg = fields[pkg_col]
        ver = fields[ver_col]
        
        if (pkg == "" || ver == "") next
        if (tolower(pkg) == "package" || tolower(pkg) == "name") next
        
        if (!(pkg in pkg_seen)) {
            pkg_seen[pkg] = 1
            pkg_order[++pkg_count] = pkg
        }
        
        if (is_range(ver)) {
            if (pkg in pkg_ranges) {
                pkg_ranges[pkg] = pkg_ranges[pkg] "|" ver
            } else {
                pkg_ranges[pkg] = ver
            }
        } else {
            if (pkg in pkg_versions) {
                pkg_versions[pkg] = pkg_versions[pkg] "|" ver
            } else {
                pkg_versions[pkg] = ver
            }
        }
    }
    
    END {
        # OPTIMIZED: Output package count FIRST (allows read without grep)
        printf "CSV_PKG_COUNT=%d\n", pkg_count

        # CSV carries no ecosystem info -> wildcard namespace "*:"
        # Output eval commands that MERGE with existing data instead of overwriting
        for (pkg in pkg_versions) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_EXACT_LOOKUP['\''%s'\'']+x}\" ]; then VULN_EXACT_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_EXACT_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(pkg_versions[pkg]), escape_sq(nk), escape_sq(pkg_versions[pkg])
        }
        for (pkg in pkg_ranges) {
            nk = "*:" pkg
            printf "if [ -n \"${VULN_RANGE_LOOKUP['\''%s'\'']+x}\" ]; then VULN_RANGE_LOOKUP['\''%s'\'']+=\"|%s\"; else VULN_RANGE_LOOKUP['\''%s'\'']='\''%s'\''; fi\n", escape_sq(nk), escape_sq(nk), escape_sq(pkg_ranges[pkg]), escape_sq(nk), escape_sq(pkg_ranges[pkg])
        }
    }
    '
}

# Alias for backward compatibility
parse_csv_default() {
    parse_csv_to_json "$1"
}

# Parse PURL format to lookup tables
# PURL format: pkg:type/namespace/name@version
# Example: pkg:npm/lodash@4.17.21
# Example with version range: pkg:npm/express@>=4.0.0 <4.17.0
