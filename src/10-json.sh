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

# Get all keys from a JSON object
# Usage: json_keys "$json"
json_keys() {
    local json="$1"
    # Return only the top-level keys (children of the root object).
    # Use an awk-based parser that respects strings, escapes and nesting depth.
    echo "$json" | tr '\n' ' ' | awk '
    {
        s=$0
        depth=0
        in_str=0
        prev=""
        key=""
        collecting=0
        for(i=1;i<=length(s);i++){
            c=substr(s,i,1)
            if(in_str){
                if(c=="\"" && prev!="\\"){
                    in_str=0
                    # look ahead for next non-space char
                    j=i+1
                    nextc=""
                    while(j<=length(s)){
                        nc=substr(s,j,1)
                        if(nc ~ /[[:space:]]/){ j++; continue }
                        nextc=nc
                        break
                    }
                    if(nextc==":" && depth==1){ print key }
                    collecting=0
                    key=""
                } else {
                    if(collecting==1) key = key c
                }
            } else {
                if(c=="\""){
                    in_str=1
                    collecting=1
                    key=""
                } else if(c=="{"){
                    depth++
                } else if(c=="}"){
                    depth--
                }
            }
            prev=c
        }
    }' | sort -u
}

# Check if JSON object has a key
# Usage: json_has_key "$json" "key"
json_has_key() {
    local json="$1"
    local key="$2"
    local escaped_key=$(escape_regex "$key")
    if echo "$json" | grep -qE "\"$escaped_key\"[[:space:]]*:"; then
        return 0
    fi
    return 1
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

# Iterate over array elements (outputs one element per line)
# Usage: json_array_iterate "$json_array"
json_array_iterate() {
    local json="$1"
    local len=$(json_array_length "$json")
    local i=0
    while [ $i -lt $len ]; do
        local elem=$(json_array_get "$json" $i)
        # Remove quotes from string elements
        echo "$elem" | sed 's/^"//;s/"$//'
        i=$((i + 1))
    done
}

# Count keys in JSON object (object length)
# OPTIMIZED: Uses fast pattern matching instead of full JSON parsing
# Works for both compact and formatted JSON
# Usage: json_object_length "$json"
json_object_length() {
    local json="$1"
    # Fast method: count occurrences of "key": { pattern (with optional whitespace)
    # This works for both compact JSON ("key":{) and formatted JSON ("key": {)
    local count
    count=$(echo "$json" | tr -d '\n\r\t' | grep -oE '"[^"]+"\s*:\s*\{' | wc -l | tr -d ' ')
    echo "${count:-0}"
}

# Merge two JSON objects (simple merge, second overwrites first)
# Usage: json_merge "$json1" "$json2"
json_merge() {
    # Merge two top-level JSON objects (both expected as object strings)
    # - keys are merged
    # - when a key exists in both, try to merge their versions and versions_range arrays
    local json1="$1"
    local json2="$2"

    # Build a set of all top-level keys
    local keys1=$(json_keys "$json1")
    local keys2=$(json_keys "$json2")
    local all_keys="$(printf '%s\n%s' "$keys1" "$keys2" | sort -u)"

    local out="{"
    local first=true

    for key in $all_keys; do
        [ -z "$key" ] && continue

        # Extract object for this key from both inputs
        local obj1=$(json_get_object "$json1" "$key")
        local obj2=$(json_get_object "$json2" "$key")

        # Normalize empty objects
        [ -z "$obj1" ] && obj1='{}'
        [ -z "$obj2" ] && obj2='{}'

        local merged_obj=""

        # If one of objects is empty, take the other
        if [ "$obj1" = "{}" ] && [ "$obj2" = "{}" ]; then
            merged_obj="{}"
        elif [ "$obj1" = "{}" ]; then
            merged_obj="$obj2"
        elif [ "$obj2" = "{}" ]; then
            merged_obj="$obj1"
        else
            # Merge versions and ranges from both objects into unique arrays
            declare -A seen_versions
            declare -A seen_ranges
            local versions_list=()
            local ranges_list=()

            # Helper to add array items into set/array
            add_items() {
                local arr_json="$1"
                local kind="$2" # version|range
                # iterate elements
                local len=$(json_array_length "$arr_json")
                local i=0
                while [ $i -lt $len ]; do
                    local v=$(json_array_get "$arr_json" $i)
                    # Strip surrounding quotes if present
                    v=$(echo "$v" | sed 's/^"//;s/"$//')
                    if [ -n "$v" ]; then
                        if [ "$kind" = "version" ]; then
                            if [ -z "${seen_versions[$v]+x}" ]; then
                                seen_versions[$v]=1
                                versions_list+=("$v")
                            fi
                        else
                            if [ -z "${seen_ranges[$v]+x}" ]; then
                                seen_ranges[$v]=1
                                ranges_list+=("$v")
                            fi
                        fi
                    fi
                    i=$((i+1))
                done
            }

            # Extract arrays from objects if present
            local v1=$(json_get_array "$obj1" "versions")
            local v2=$(json_get_array "$obj2" "versions")
            local r1=$(json_get_array "$obj1" "versions_range")
            local r2=$(json_get_array "$obj2" "versions_range")

            add_items "$v1" "version"
            add_items "$v2" "version"
            add_items "$r1" "range"
            add_items "$r2" "range"

            # Build merged object JSON
            merged_obj="{"
            local has=false
            if [ ${#versions_list[@]} -gt 0 ]; then
                merged_obj+="\"versions\":["
                local firstv=true
                for vv in "${versions_list[@]}"; do
                    if [ "$firstv" = false ]; then merged_obj+=","; fi
                    firstv=false
                    merged_obj+="\"${vv}\""
                done
                merged_obj+="]"
                has=true
            fi
            if [ ${#ranges_list[@]} -gt 0 ]; then
                if [ "$has" = true ]; then merged_obj+=","; fi
                merged_obj+="\"versions_range\":["
                local firstr=true
                for rr in "${ranges_list[@]}"; do
                    if [ "$firstr" = false ]; then merged_obj+=","; fi
                    firstr=false
                    merged_obj+="\"${rr}\""
                done
                merged_obj+="]"
            fi
            merged_obj+="}"
        fi

        # Append to output
        if [ "$first" = true ]; then
            out+="\"${key}\":${merged_obj}"
            first=false
        else
            out+=",\"${key}\":${merged_obj}"
        fi
    done

    out+="}"
    echo "$out"
}
