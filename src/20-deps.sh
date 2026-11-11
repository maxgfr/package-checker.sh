# Check that the required tools are installed (default: curl, used to
# download remote sources). Feed generation also needs jq and friends.
check_dependencies() {
    local tool
    [ $# -gt 0 ] || set -- curl
    for tool in "$@"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "❌ Error: '$tool' must be installed to run this command"
            exit "$EXIT_ERROR"
        fi
    done
}

# Directory of the real script file, symlinks resolved (Homebrew and the
# Docker images run it through /usr/local/bin/package-checker). Empty when the
# script is piped (curl ... | bash). Sets SCRIPT_HOME once.
resolve_script_home() {
    [ -z "${SCRIPT_HOME+x}" ] || return 0
    SCRIPT_HOME=""
    local path="${BASH_SOURCE[0]:-}" link hops=0
    [ -n "$path" ] && [ -f "$path" ] || return 0
    while [ -L "$path" ] && [ "$hops" -lt 32 ]; do
        link=$(readlink "$path") || break
        case "$link" in
            /*) path="$link" ;;
            *) path="$(dirname "$path")/$link" ;;
        esac
        hops=$((hops + 1))
    done
    SCRIPT_HOME=$(cd "$(dirname "$path")" 2>/dev/null && pwd) || SCRIPT_HOME=""
}

# Homebrew prefix, computed once (brew --prefix takes ~0.1 s). Sets
# BREW_PREFIX ("" without Homebrew).
resolve_brew_prefix() {
    [ -z "${BREW_PREFIX+x}" ] || return 0
    BREW_PREFIX=""
    if command -v brew &> /dev/null; then
        BREW_PREFIX=$(brew --prefix 2>/dev/null) || BREW_PREFIX=""
    fi
}

# Temporary files removed when the script exits, whatever the exit path.
PC_TEMP_FILES=()
PC_CLEANUP_TRAP=false
pc_cleanup_temp_files() {
    [ ${#PC_TEMP_FILES[@]} -eq 0 ] || rm -f -- "${PC_TEMP_FILES[@]}"
}
# Register a temp file for cleanup. The EXIT trap is installed once and keeps
# any EXIT trap already set (it runs after the cleanup).
register_temp_file() {
    PC_TEMP_FILES+=("$1")
    [ "$PC_CLEANUP_TRAP" = true ] && return 0
    PC_CLEANUP_TRAP=true
    local previous
    previous=$(trap -p EXIT)
    if [ -n "$previous" ]; then
        eval "set -- $previous"   # trap -- 'command' EXIT
        trap "pc_cleanup_temp_files; $3" EXIT
    else
        trap pc_cleanup_temp_files EXIT
    fi
}

