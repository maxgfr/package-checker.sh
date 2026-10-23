# Pub (Dart) version comparator. Routed to from compare_versions_eco when
# CHECK_ECO=pub.
#
# Pub orders build metadata, unlike semver: 0.3.5 < 0.3.5+1 < 0.3.5+2 (pub
# publishes fixes as "+N" builds). Versions compare as semver first; when they
# are equal, a version without build metadata is lower, and two builds compare
# like pre-release identifiers (dot-separated, numeric parts numerically).
#
# Contract mirrors compare_versions: sets COMPARE_RESULT (-1/0/1), no stdout,
# no subshell.
compare_versions_pub() {
    local v1="$1" v2="$2" build1="" build2=""
    [[ "$v1" == *+* ]] && build1="${v1#*+}"
    [[ "$v2" == *+* ]] && build2="${v2#*+}"
    compare_versions "${v1%%+*}" "${v2%%+*}"
    [ "$COMPARE_RESULT" = 0 ] || return 0
    if [ -z "$build1" ] && [ -z "$build2" ]; then return 0; fi
    if [ -z "$build1" ]; then COMPARE_RESULT=-1; return 0; fi
    if [ -z "$build2" ]; then COMPARE_RESULT=1; return 0; fi
    compare_versions "0.0.0-$build1" "0.0.0-$build2"
}
