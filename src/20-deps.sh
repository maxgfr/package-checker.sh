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

