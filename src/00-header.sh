#!/usr/bin/env bash
# GENERATED FILE NOTICE: script.sh is built from src/ by ./build.sh — edit src/, not script.sh.

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

# Plain POSIX syntax up to the version check, so `sh script.sh` gets this
# message instead of a parse error.
case "${BASH_VERSION:-}" in
    ""|[0-3].*)
        printf '%s\n' 'Error: package-checker requires Bash 4 or newer (macOS: brew install bash).' >&2
        exit 2 ;;
esac
set -e

# Exit codes: 0 = no vulnerable package, 1 = vulnerable packages found,
# EXIT_ERROR = the scan could not run or complete (bad usage, unreadable or
# empty data, unexpected failure). CI treats any non-zero code as a failure.
EXIT_ERROR=2

# Byte-wise string comparison and character classes: version ordering
# ([[ a < b ]]), awk ranges and sort must not depend on the user's locale
# (5.0.0-beta1 vs 5.0.0-RC1 orders differently under fr_FR and C).
export LC_ALL=C

# Version - automatically updated by release workflow
# Last release: https://github.com/maxgfr/package-checker.sh/releases
# NOTE: this exact 'VERSION="..."' format is sed-matched by .releaserc.json — do not reformat.
VERSION="1.16.5"

# Default configuration
CONFIG_FILE=".package-checker.config.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
LOADED_SOURCE_COUNT=0
FOUND_VULNERABLE=0
VULNERABLE_PACKAGES=()

# Pre-built vulnerability lookup tables (for O(1) lookup)
declare -A VULN_EXACT_LOOKUP      # VULN_EXACT_LOOKUP[package]="ver1|ver2|..."
declare -A VULN_RANGE_LOOKUP      # VULN_RANGE_LOOKUP[package]="range1|range2|..."
# Per finding (key "eco:package@version"): the most severe advisory's fields,
# every matching advisory, and the version that fixes them all.
declare -A VULN_METADATA_SEVERITY # ="critical|high|medium|low"
declare -A VULN_METADATA_GHSA     # ="GHSA-xxxx-xxxx-xxxx"
declare -A VULN_METADATA_CVE      # ="CVE-YYYY-NNNNN"
declare -A VULN_METADATA_SOURCE   # ="ghsa|osv|custom" (merged: "ghsa, osv")
declare -A VULN_ADVISORIES        # ="sev;ghsa;cve;src;fix;id||..." (all matching advisories)
declare -A VULN_METADATA_FIX      # ="fix_version"
declare -A VULN_RECORDS           # lookup key (eco:name@version or eco:name:range) -> advisory records

# Configuration defaults (can be overridden by config file)
CONFIG_IGNORE_PATHS=("node_modules" ".yarn" ".git" "vendor")
CONFIG_DEPENDENCY_TYPES=("dependencies" "devDependencies" "optionalDependencies")
CONFIG_ECOSYSTEMS=""  # optional feed-loading override from config (options.ecosystems)
CONFIG_RUNTIME_CHECK=true  # options.runtime_check (--no-runtime-check overrides)

# Project files that could not be read (an incomplete scan is never clean)
UNREADABLE_FILE_COUNT=0

# Ecosystem registry lookup tables — derived from ECOSYSTEM_REGISTRY by
# build_ecosystem_tables() (see src/50-ecosystems/01-registry.sh)
declare -A LOCKFILE_PARSER   # LOCKFILE_PARSER[basename]="analyze_fn"
declare -A LOCKFILE_ECO      # LOCKFILE_ECO[basename]="purl-type"
KNOWN_LOCKFILE_ALIASES=""    # space-separated unique alias list (validation + help)

# Ecosystems detected in the scanned project (eco -> 1); drives default-feed loading
declare -A DETECTED_ECOSYSTEMS

# govulncheck call analysis of Go findings (--go-reachability)
declare -A VULN_REACHABILITY      # VULN_REACHABILITY[dir|golang:module@version]="called|not called"

# CycloneDX SBOMs given with --sbom (path -> 1), scanned as project inventories
declare -A SBOM_FILES
declare -A SBOM_COMPONENTS   # path -> "eco|name|version" lines (cyclonedx_components)
