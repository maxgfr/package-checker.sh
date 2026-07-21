# Comparator dispatch — routes a candidate/range version comparison to the
# ecosystem-appropriate comparator. Matching code passes CHECK_ECO (set by
# check_vulnerability); everything that is not a special-cased ecosystem falls
# through to the unchanged npm-semver compare_versions (behavior freeze).
#
# Contract mirrors compare_versions: sets the global COMPARE_RESULT (-1/0/1),
# no stdout, no subshell.
compare_versions_eco() {
    case "$1" in
        golang) compare_versions_go "$2" "$3" ;;
        *)      compare_versions "$2" "$3" ;;
    esac
}
