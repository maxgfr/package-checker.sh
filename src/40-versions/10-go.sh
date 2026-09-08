# Go module versions use the shared semver comparator after removing the
# module-specific leading v. Pseudo-versions follow prerelease ordering.
compare_versions_go() {
    compare_versions "${1#v}" "${2#v}"
}
