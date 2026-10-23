# ============================================================================
# Runtime version check (Node.js, PHP)
#
# A project also targets a runtime: .nvmrc, a Docker base image, the PHP
# version composer resolves for... Those versions are checked against the
# runtime feed (data/osv-runtime.purl, lines pkg:runtime/<node|php>@<range>,
# see fetch_runtime in src/60-feeds.sh).
#
#   * an exact version (22.1.0) is a normal finding: [runtime] node@22.1.0;
#   * a release line (20, 8.3, node:20-alpine) floats to its latest release:
#     it is reported only when no release of the line is fixed (EOL line);
#   * a range (>=18, ^8.1) is reported when its lowest admitted version is
#     vulnerable.
# Lines and ranges are yellow warnings only: they never change the exit code.
# Values that name no version (lts/*, latest, ${NODE_VERSION}) are ignored.
#
# Runtime files are discovered with the lockfiles (discover_project_files) but
# are not ecosystem registry rows: they select no GHSA/OSV feed.
# ============================================================================

# find -name patterns of the runtime version files (package.json and the
# GitHub Actions workflows are matched separately by discover_project_files).
RUNTIME_FILE_NAMES=(.nvmrc .node-version .tool-versions .php-version composer.json composer.lock 'Dockerfile*' '*.Dockerfile' '*.dockerfile')

# Warnings printed again in the summary (one line per file and runtime).
RUNTIME_WARNINGS=()

# A line any file naming a runtime version contains (a superset of what
# runtime_specs reads): most package.json files have no engines and must not
# pull the runtime feed.
RUNTIME_HINT_RE='"(engines|volta)"[[:space:]]*:|"php"[[:space:]]*:|"platform-overrides"|(node|php)-version[[:space:]]*:|^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]].*(node|php)|^(nodejs|node|php)[[:space:]]|^[[:space:]]*[vV]?[0-9]'

# Print the files of a newline-separated list that may name a runtime version
# (one grep for all of them).
runtime_files_with_versions() {
    [ -n "$1" ] || return 0
    printf '%s\n' "$1" | tr '\n' '\0' | xargs -0 grep -lE -- "$RUNTIME_HINT_RE" 2>/dev/null || true
}

# Classify a discovered file. Sets RUNTIME_KIND; returns 1 when the file names
# no runtime version.
runtime_file_kind() {
    local file="$1"
    case "${file##*/}" in
        .nvmrc|.node-version) RUNTIME_KIND=node_version ;;
        .php-version) RUNTIME_KIND=php_version ;;
        .tool-versions) RUNTIME_KIND=tool_versions ;;
        package.json) RUNTIME_KIND=package_json ;;
        composer.json) RUNTIME_KIND=composer_json ;;
        composer.lock) RUNTIME_KIND=composer_lock ;;
        Dockerfile*|*.Dockerfile|*.dockerfile) RUNTIME_KIND=dockerfile ;;
        *.yml|*.yaml)
            [[ "$file" == */.github/workflows/* ]] || return 1
            RUNTIME_KIND=workflow ;;
        *) return 1 ;;
    esac
}

# Print "runtime|spec" for every runtime version a file names, raw (quotes
# and comments removed).
runtime_specs() {
    local file="$1" content obj value
    runtime_file_kind "$file" || return 0
    case "$RUNTIME_KIND" in
        node_version|php_version)
            local rt=node
            [ "$RUNTIME_KIND" = node_version ] || rt=php
            awk -v rt="$rt" '{ sub(/\r$/, ""); sub(/#.*/, "") } NF { print rt "|" $1; exit }' "$file"
            ;;
        tool_versions)
            # asdf / mise: "nodejs 22.1.0 20.0.0" (every listed version is installed)
            awk '{ sub(/\r$/, ""); sub(/#.*/, "") }
                $1 == "nodejs" || $1 == "node" || $1 == "php" {
                    rt = ($1 == "php") ? "php" : "node"
                    for (i = 2; i <= NF; i++) print rt "|" $i
                }' "$file"
            ;;
        package_json)
            grep -qE '"(engines|volta)"[[:space:]]*:' "$file" || return 0
            content=$(cat "$file")
            for obj in engines volta; do
                value=$(json_get_value "$(json_get_object "$content" "$obj")" node)
                [ -z "$value" ] || [ "$value" = null ] || printf 'node|%s\n' "$value"
            done
            ;;
        composer_json)
            grep -q '"php"' "$file" || return 0
            content=$(cat "$file")
            # config.platform.php: the PHP version composer resolves for
            value=$(json_get_value "$(json_get_object "$(json_get_object "$content" config)" platform)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            value=$(json_get_value "$(json_get_object "$content" require)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            ;;
        composer_lock)
            grep -q '"platform-overrides"' "$file" || return 0
            value=$(json_get_value "$(json_get_object "$(cat "$file")" platform-overrides)" php)
            [ -z "$value" ] || [ "$value" = null ] || printf 'php|%s\n' "$value"
            ;;
        dockerfile)
            # FROM [--platform=...] [registry/][library/]node:TAG[@digest] [AS name]
            awk '{ sub(/\r$/, "") }
                toupper($1) == "FROM" {
                    i = 2
                    while (i <= NF && substr($i, 1, 2) == "--") i++
                    image = $i
                    sub(/@.*/, "", image)
                    colon = 0
                    for (j = length(image); j > 0; j--) {
                        c = substr(image, j, 1)
                        if (c == "/") break
                        if (c == ":") { colon = j; break }
                    }
                    if (colon == 0) next
                    name = tolower(substr(image, 1, colon - 1))
                    tag = substr(image, colon + 1)
                    sub(/^(index\.)?docker\.io\//, "", name)
                    sub(/^library\//, "", name)
                    if (name != "node" && name != "php") next
                    # Variant suffixes name no version: 20-alpine, 8.3.10-fpm-bookworm
                    if (match(tag, /^[vV]?[0-9]+(\.[0-9]+)*/) && (RLENGTH == length(tag) || substr(tag, RLENGTH + 1, 1) == "-"))
                        tag = substr(tag, 1, RLENGTH)
                    print name "|" tag
                }' "$file"
            ;;
        workflow)
            # node-version: 22.1.0 | [18, 20] | a block list; php-version: likewise
            awk '
            function emit(rt, v) {
                gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", v)
                if (v != "") print rt "|" v
            }
            { sub(/\r$/, "") }
            list_rt != "" {
                if (match($0, /^[[:space:]]*-[[:space:]]+/) && RLENGTH > list_indent) {
                    v = substr($0, RLENGTH + 1)
                    sub(/[[:space:]]+#.*/, "", v)
                    emit(list_rt, v)
                    next
                }
                if ($0 !~ /^[[:space:]]*(#.*)?$/) list_rt = ""
            }
            match($0, /^[[:space:]]*(-[[:space:]]+)?(node|php)-version:/) {
                key_indent = RLENGTH
                rt = ($0 ~ /php-version:/) ? "php" : "node"
                v = substr($0, RLENGTH + 1)
                sub(/[[:space:]]+#.*/, "", v)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                if (v == "") { list_rt = rt; list_indent = key_indent - length(rt "-version:"); next }
                if (substr(v, 1, 1) == "[") {
                    gsub(/[][]/, "", v)
                    n = split(v, items, ",")
                    for (k = 1; k <= n; k++) emit(rt, items[k])
                } else emit(rt, v)
            }' "$file"
            ;;
    esac
}

# Normalize a raw spec: no quotes or blanks at the ends, no "v" before a
# version, ".x" / ".*" wildcards dropped (20.x -> 20). Sets RT_SPEC.
runtime_normalize_spec() {
    local s="$1"
    s="${s#"${s%%[![:space:]\"\']*}"}"
    s="${s%"${s##*[![:space:]\"\']}"}"
    [[ "$s" == [vV][0-9]* ]] && s="${s:1}"
    while [[ "$s" == *.[xX*] ]]; do s="${s%.?}"; done
    RT_SPEC="$s"
}

# Lowest version a range admits, padded to x.y.z (>=18 -> 18.0.0,
# ^8.1 || ^7.4 -> 7.4.0). Alternatives without a lower bound (<20, *) are
# skipped. Sets RT_FLOOR (empty when no alternative has one).
runtime_range_floor() {
    local spec="${1//||/|}" alt token v
    local -a alts tokens parts
    RT_FLOOR=""
    IFS='|' read -ra alts <<< "$spec"
    for alt in "${alts[@]}"; do
        alt="${alt//,/ }"
        # Glue a detached operator to its version: ">= 18" -> ">=18"
        while [[ "$alt" =~ ^(.*)(\>=|\>|~\>|~=|\^|~|==|=)[[:space:]]+(.*)$ ]]; do
            alt="${BASH_REMATCH[1]}${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
        done
        read -ra tokens <<< "$alt"
        v=""
        for token in "${tokens[@]}"; do
            if [[ "$token" =~ ^(\>=|\>|~\>|~=|\^|~|==|=)?[vV]?([0-9]+(\.[0-9xX*]+)*)$ ]]; then
                v="${BASH_REMATCH[2]}"
                break
            fi
        done
        [ -n "$v" ] || continue
        while [[ "$v" == *.[xX*] ]]; do v="${v%.?}"; done
        IFS='.' read -ra parts <<< "$v"
        v="${parts[0]}.${parts[1]:-0}.${parts[2]:-0}"
        if [ -z "$RT_FLOOR" ]; then
            RT_FLOOR="$v"
        else
            compare_versions "$v" "$RT_FLOOR"
            [ "$COMPARE_RESULT" != -1 ] || RT_FLOOR="$v"
        fi
    done
}

# Integer key of a plain x.y.z version (missing parts count as 0), ordered
# like compare_versions for such versions. Sets RT_KEY; returns 1 for any
# other version (pre-release, 6+ digit minor or patch).
_rt_numeric_key() {
    [[ "$1" =~ ^[vV]?([0-9]{1,8})(\.([0-9]{1,5}))?(\.([0-9]{1,5}))?$ ]] || return 1
    RT_KEY=$(( 10#${BASH_REMATCH[1]} * 10000000000 + 10#${BASH_REMATCH[3]:-0} * 100000 + 10#${BASH_REMATCH[5]:-0} ))
}

# Per runtime, the loaded feed indexed once (runtime_index): RT_INDEX[rt]
# holds one "range|ident|fix_key|fix" row per advisory record, RT_COND
# ["rt|range"] the range as integer comparators ("op key op key", "*" or "!";
# empty when a bound is not plain x.y.z: version_in_range decides).
declare -A RT_INDEX=() RT_COND=() RT_AFFECTED_CACHE=()

runtime_index() {
    local rt="$1" key="runtime:$1" range rec recs rows="" cond parsed i ok
    local ghsa cve fix id ident fix_key
    local -a tokens
    while IFS= read -r range; do
        [ -n "$range" ] || continue
        cond=""
        case "$range" in
            # Alternatives and intervals: version_in_range decides.
            *"|"*|*"["*|*"("*) ;;
            *)
                [ -n "${RANGE_CACHE[runtime|$range]+x}" ] || _prepare_range "$range" "runtime|$range"
                parsed="${RANGE_CACHE[runtime|$range]}"
                case "$parsed" in
                    "*"|"!") cond="$parsed" ;;
                    *)
                        ok=true
                        read -ra tokens <<< "$parsed"
                        for (( i = 0; i < ${#tokens[@]}; i += 2 )); do
                            _rt_numeric_key "${tokens[i + 1]}" || { ok=false; break; }
                            cond+="${tokens[i]} $RT_KEY "
                        done
                        [ "$ok" = true ] || cond="" ;;
                esac ;;
        esac
        RT_COND["$rt|$range"]="${cond% }"
        recs="${VULN_RECORDS[$key:$range]:-}"
        while [ -n "$recs" ]; do
            # "severity;ghsa;cve;source;fix;id", split without a subshell
            rec="${recs%%$'\n'*}"
            recs="${recs#*$'\n'}"
            [ "$rec" != "$recs" ] || recs=""
            rec="${rec#*;}"; ghsa="${rec%%;*}"
            rec="${rec#*;}"; cve="${rec%%;*}"
            rec="${rec#*;}"; rec="${rec#*;}"; fix="${rec%%;*}"
            id="${rec#*;}"
            ident="${cve:-${ghsa:-$id}}"
            [ -n "$ident" ] || continue
            fix_key=""
            [ -z "$fix" ] || ! _rt_numeric_key "$fix" || fix_key="$RT_KEY"
            rows+="$range|$ident|$fix_key|$fix"$'\n'
        done
    done <<< "${VULN_RANGE_LOOKUP[$key]:-}"
    RT_INDEX["$rt"]="$rows"
}

# Advisories of a runtime that affect one version. Sets RT_IDS (sorted,
# space-separated CVE or advisory ids) and RT_FIX (for each advisory, the
# lowest fixed version above VERSION; the highest of those, so that one
# upgrade fixes them all). Returns 1 when no advisory affects VERSION.
# Results are cached per version: workflows repeat the same lines.
runtime_affected() {
    local rt="$1" version="$2" cached="$1|$2"
    if [ -n "${RT_AFFECTED_CACHE[$cached]+x}" ]; then
        cached="${RT_AFFECTED_CACHE[$cached]}"
        [ -n "$cached" ] || return 1
        RT_IDS="${cached%%|*}" RT_FIX="${cached#*|}"
        return 0
    fi
    [ -n "${RT_INDEX[$rt]+x}" ] || runtime_index "$rt"
    local key="runtime:$1" range ident fix_key fix cond vkey="" i matched candidate rec lk lf
    local severity ghsa cve source id
    local -A hit=() lowest_key=() lowest_fix=() range_hit=()
    local -a c exacts
    RT_IDS="" RT_FIX=""
    CHECK_ECO=runtime
    ! _rt_numeric_key "$version" || vkey="$RT_KEY"
    while IFS='|' read -r range ident fix_key fix; do
        [ -n "$range" ] || continue
        if [ -z "${range_hit[$range]+x}" ]; then
            cond="${RT_COND[$rt|$range]}"
            matched=0
            if [ -n "$vkey" ] && [ -n "$cond" ]; then
                case "$cond" in
                    "*") matched=1 ;;
                    "!") ;;
                    *)
                        matched=1
                        read -ra c <<< "$cond"
                        for (( i = 0; i < ${#c[@]}; i += 2 )); do
                            case "${c[i]}" in
                                ">=") (( vkey >= c[i + 1] )) ;;
                                ">") (( vkey > c[i + 1] )) ;;
                                "<") (( vkey < c[i + 1] )) ;;
                                "<=") (( vkey <= c[i + 1] )) ;;
                                "=") (( vkey == c[i + 1] )) ;;
                                "!=") (( vkey != c[i + 1] )) ;;
                            esac || { matched=0; break; }
                        done ;;
                esac
            elif version_in_range "$version" "$range"; then
                matched=1
            fi
            range_hit["$range"]=$matched
        fi
        [ "${range_hit[$range]}" = 0 ] || hit["$ident"]=1
        [ -n "$fix" ] || continue
        # Lowest fix above VERSION, per advisory (integer keys when both
        # sides are plain x.y.z, compare_versions otherwise).
        lk="${lowest_key[$ident]:-}" lf="${lowest_fix[$ident]:-}"
        if [ -n "$vkey" ] && [ -n "$fix_key" ]; then
            (( fix_key > vkey )) || continue
            if [ -n "$lk" ]; then
                (( fix_key < lk )) || continue
            elif [ -n "$lf" ]; then
                compare_versions "$fix" "$lf"
                [ "$COMPARE_RESULT" = -1 ] || continue
            fi
        else
            compare_versions "$fix" "$version"
            [ "$COMPARE_RESULT" = 1 ] || continue
            if [ -n "$lf" ]; then
                compare_versions "$fix" "$lf"
                [ "$COMPARE_RESULT" = -1 ] || continue
            fi
        fi
        lowest_key["$ident"]="$fix_key"
        lowest_fix["$ident"]="$fix"
    done <<< "${RT_INDEX[$rt]}"
    IFS='|' read -ra exacts <<< "${VULN_EXACT_LOOKUP[$key]:-}"
    for candidate in "${exacts[@]}"; do
        [ -n "$candidate" ] && version_matches_vulnerable "$version" "$candidate" || continue
        while IFS= read -r rec; do
            IFS=';' read -r severity ghsa cve source fix id <<< "$rec"
            ident="${cve:-${ghsa:-$id}}"
            [ -z "$ident" ] || hit["$ident"]=1
        done <<< "${VULN_RECORDS[$key@$candidate]:-}"
    done
    if [ ${#hit[@]} -eq 0 ]; then
        RT_AFFECTED_CACHE["$rt|$version"]=""
        return 1
    fi
    RT_IDS=$(printf '%s\n' "${!hit[@]}" | sort | tr '\n' ' ')
    RT_IDS="${RT_IDS% }"
    for ident in "${!hit[@]}"; do
        fix="${lowest_fix[$ident]:-}"
        [ -n "$fix" ] || continue
        if [ -n "$RT_FIX" ]; then
            compare_versions "$fix" "$RT_FIX"
            [ "$COMPARE_RESULT" = 1 ] || continue
        fi
        RT_FIX="$fix"
    done
    RT_AFFECTED_CACHE["$rt|$version"]="$RT_IDS|$RT_FIX"
    return 0
}

runtime_display_name() {
    case "$1" in
        node) echo "Node.js" ;;
        php) echo "PHP" ;;
        *) echo "$1" ;;
    esac
}

# Check the runtime versions of every RUNTIME_FILES entry (see the header).
scan_runtimes() {
    local file rt spec probe kind count before=${#VULNERABLE_PACKAGES[@]} warned=0
    local -A seen=() warn_specs=() warn_ids=() warn_fix=() warn_kind=()
    local ids n message label
    count=$(printf '%s\n' "$RUNTIME_FILES" | wc -l | tr -d ' ')
    echo "🧩 Checking runtime versions in $count file(s)..."
    while IFS= read -r file; do
        # Unreadable files never get here (runtime_files_with_versions).
        [ -n "$file" ] || continue
        # Per runtime: the specs to warn about, their advisories, the fix.
        warn_specs=() warn_ids=() warn_fix=() warn_kind=()
        while IFS='|' read -r rt spec; do
            [ -n "$rt" ] || continue
            runtime_normalize_spec "$spec"
            spec="$RT_SPEC"
            [ -z "${seen[$file|$rt|$spec]+x}" ] || continue
            seen["$file|$rt|$spec"]=1
            if [[ "$spec" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                check_vulnerability "runtime" "$rt" "$spec" "$file" || true
                continue
            fi
            # Warnings belong to full scans, not to a --package-name lookup.
            [ -z "${PACKAGE_FILTER:-}" ] || continue
            if [[ "$spec" =~ ^[0-9]+$ ]]; then
                probe="$spec.99999.99999" kind=line
            elif [[ "$spec" =~ ^[0-9]+\.[0-9]+$ ]]; then
                probe="$spec.99999" kind=line
            elif [[ "$spec" =~ [\<\>=^~|,*\ ] ]]; then
                runtime_range_floor "$spec"
                [ -n "$RT_FLOOR" ] || continue
                probe="$RT_FLOOR" kind=range
            else
                continue
            fi
            runtime_affected "$rt" "$probe" || continue
            warn_specs["$rt"]+="${warn_specs[$rt]:+, }$spec"
            warn_ids["$rt"]+="${warn_ids[$rt]:+ }$RT_IDS"
            [ "$kind" = line ] && [ -n "${warn_kind[$rt]:-}" ] || warn_kind["$rt"]="$kind"
            if [ -n "$RT_FIX" ]; then
                if [ -z "${warn_fix[$rt]:-}" ]; then
                    warn_fix["$rt"]="$RT_FIX"
                else
                    compare_versions "$RT_FIX" "${warn_fix[$rt]}"
                    [ "$COMPARE_RESULT" != 1 ] || warn_fix["$rt"]="$RT_FIX"
                fi
            fi
        done < <(runtime_specs "$file")

        for rt in "${!warn_specs[@]}"; do
            # Newest advisories first (CVE-YYYY-NNNN).
            # shellcheck disable=SC2086 # space-separated advisory ids
            ids=$(printf '%s\n' ${warn_ids[$rt]} | sort -u | sort -t- -k2,2nr -k3,3nr)
            n=$(printf '%s\n' "$ids" | wc -l | tr -d ' ')
            ids=$(printf '%s\n' "$ids" | head -n 3 | tr '\n' ' ')
            ids="${ids% }"
            ids="${ids// /, }"
            [ "$n" -le 3 ] || ids+=" (+$((n - 3)) more)"
            label="$(runtime_display_name "$rt") ${warn_specs[$rt]}"
            if [ "${warn_kind[$rt]}" = line ]; then
                message="$label: no release of this line fixes $ids"
                [ -z "${warn_fix[$rt]:-}" ] || message+="; move to >= ${warn_fix[$rt]}"
            else
                message="$label allows vulnerable versions ($ids)"
                [ -z "${warn_fix[$rt]:-}" ] || message+="; raise the minimum to >= ${warn_fix[$rt]}"
            fi
            echo -e "${YELLOW}⚠️  [$file] $message${NC}"
            RUNTIME_WARNINGS+=("[$file] $message")
            warned=$((warned + 1))
        done
    done <<< "$RUNTIME_FILES"

    if [ "${#VULNERABLE_PACKAGES[@]}" -eq "$before" ] && [ "$warned" -eq 0 ]; then
        echo -e "${GREEN}✓ Runtime versions: no known vulnerability${NC}"
    fi
}
