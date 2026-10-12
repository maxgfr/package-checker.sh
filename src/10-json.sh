# ============================================================================
# Pure Bash JSON Parser Functions (no jq dependency)
# ============================================================================

# Escape special regex characters in a string
escape_regex() {
    local str="$1"
    printf '%s' "$str" | sed 's/[.[\*^$()+?{|\\]/\\&/g'
}

# Get a simple string value from JSON by key (top-level only)
# Usage: json_get_value "$json" "key"
json_get_value() {
    local json="$1"
    local key="$2"
    local escaped_key=$(escape_regex "$key")
    # Match "key": "value" or "key": value (for numbers/booleans)
    local result=$(echo "$json" | grep -oE "\"$escaped_key\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+|true|false|null)" | head -1)
    if [ -n "$result" ]; then
        echo "$result" | sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*//' | sed 's/^"//;s/"$//'
    fi
}

# Get array length from JSON (for simple arrays at top level)
# Usage: json_array_length "$json"
json_array_length() {
    local json="$1"
    # Count elements by counting commas + 1 (or 0 if empty)
    local trimmed=$(echo "$json" | tr -d '\n\r\t ' | sed 's/^\[//;s/\]$//')
    if [ -z "$trimmed" ] || [ "$trimmed" = "[]" ]; then
        echo "0"
        return
    fi
    # Count top-level commas (not inside nested structures)
    local count=1
    local depth=0
    local in_string=false
    local prev_char=""
    local i=0
    local len=${#trimmed}
    
    while [ $i -lt $len ]; do
        local char="${trimmed:$i:1}"
        if [ "$in_string" = true ]; then
            if [ "$char" = '"' ] && [ "$prev_char" != "\\" ]; then
                in_string=false
            fi
        else
            case "$char" in
                '"') in_string=true ;;
                '[' | '{') depth=$((depth + 1)) ;;
                ']' | '}') depth=$((depth - 1)) ;;
                ',') [ $depth -eq 0 ] && count=$((count + 1)) ;;
            esac
        fi
        prev_char="$char"
        i=$((i + 1))
    done
    echo "$count"
}

# Get array element at index from JSON array
# Usage: json_array_get "$json_array" index
json_array_get() {
    local json="$1"
    local index="$2"
    local trimmed=$(echo "$json" | tr -d '\n\r\t' | sed 's/^[[:space:]]*\[//;s/\][[:space:]]*$//')
    
    local current=0
    local depth=0
    local in_string=false
    local prev_char=""
    local start=0
    local i=0
    local len=${#trimmed}
    
    while [ $i -lt $len ]; do
        local char="${trimmed:$i:1}"
        if [ "$in_string" = true ]; then
            if [ "$char" = '"' ] && [ "$prev_char" != "\\" ]; then
                in_string=false
            fi
        else
            case "$char" in
                '"') in_string=true ;;
                '[' | '{') depth=$((depth + 1)) ;;
                ']' | '}') depth=$((depth - 1)) ;;
                ',')
                    if [ $depth -eq 0 ]; then
                        if [ $current -eq $index ]; then
                            echo "${trimmed:$start:$((i - start))}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                            return
                        fi
                        current=$((current + 1))
                        start=$((i + 1))
                    fi
                    ;;
            esac
        fi
        prev_char="$char"
        i=$((i + 1))
    done
    
    # Last element
    if [ $current -eq $index ]; then
        echo "${trimmed:$start}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
    fi
}

# Get nested object value from JSON
# Usage: json_get_object "$json" "key"
json_get_object() {
    local json="$1"
    local key="$2"
    
    # Flatten JSON to single line and extract object
    local flat=$(echo "$json" | tr '\n' ' ' | tr -s ' ')
    
    # Find position of key and extract content after it
    # Use Python-like approach with awk
    echo "$flat" | awk -v key="\"$key\"" '
    {
        # Find the key
        idx = index($0, key)
        if (idx == 0) { print "{}"; exit }
        
        # Get everything after the key
        rest = substr($0, idx + length(key))
        
        # Skip whitespace and colon
        match(rest, /^[[:space:]]*:[[:space:]]*/)
        rest = substr(rest, RLENGTH + 1)
        
        # Check first character
        first = substr(rest, 1, 1)
        if (first != "{" && first != "[") { print "{}"; exit }
        
        # Count brackets to find the end
        depth = 0
        in_str = 0
        result = ""
        n = length(rest)
        
        for (i = 1; i <= n; i++) {
            c = substr(rest, i, 1)
            result = result c
            
            if (in_str) {
                if (c == "\"" && substr(rest, i-1, 1) != "\\") in_str = 0
            } else {
                if (c == "\"") in_str = 1
                else if (c == "{" || c == "[") depth++
                else if (c == "}" || c == "]") {
                    depth--
                    if (depth == 0) { print result; exit }
                }
            }
        }
        print "{}"
    }'
}

# Get array from JSON object by key
# Usage: json_get_array "$json" "key"
json_get_array() {
    local json="$1"
    local key="$2"
    local result=$(json_get_object "$json" "$key")
    # Return empty array if result is empty object or invalid
    if [ -z "$result" ] || [ "$result" = "{}" ]; then
        echo "[]"
    else
        echo "$result"
    fi
}
