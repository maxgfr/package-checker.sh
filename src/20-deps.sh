# Check that curl is installed
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        echo "❌ Error: 'curl' must be installed to run this script"
        exit 1
    fi
}

