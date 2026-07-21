#!/usr/bin/env bash
# GENERATED FILE NOTICE: script.sh is built from src/ by ./build.sh — edit src/, not script.sh.

# Package Vulnerability Checker
# Analyzes package.json and lockfiles to detect vulnerable packages from custom data sources

set -e

# Version - automatically updated by release workflow
# Last release: https://github.com/maxgfr/package-checker.sh/releases
# NOTE: this exact 'VERSION="..."' format is sed-matched by .releaserc.json — do not reformat.
VERSION="1.10.222"

# Default configuration
CONFIG_FILE=".package-checker.config.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
VULN_DATA=""
DATA_SOURCES=()
FOUND_VULNERABLE=0
VULNERABLE_PACKAGES=()
CSV_COLUMNS=()

# Pre-built vulnerability lookup tables (for O(1) lookup)
declare -A VULN_EXACT_LOOKUP      # VULN_EXACT_LOOKUP[package]="ver1|ver2|..."
declare -A VULN_RANGE_LOOKUP      # VULN_RANGE_LOOKUP[package]="range1|range2|..."
declare -A VULN_METADATA_SEVERITY # VULN_METADATA_SEVERITY[package@version OR package]="critical|high|medium|low"
declare -A VULN_METADATA_GHSA     # VULN_METADATA_GHSA[package@version OR package]="GHSA-xxxx-xxxx-xxxx"
declare -A VULN_METADATA_CVE      # VULN_METADATA_CVE[package@version OR package]="CVE-YYYY-NNNNN"
declare -A VULN_METADATA_SOURCE   # VULN_METADATA_SOURCE[package@version OR package]="ghsa|osv|custom"
declare -A VULN_ADVISORIES        # VULN_ADVISORIES[package@version]="sev;ghsa;cve;src||sev;ghsa;cve;src" (all matching advisories)
declare -A VULN_PATCHED           # VULN_PATCHED[package:GHSA-xxx]="patched_version" (highest upper bound per GHSA)
declare -A VULN_METADATA_FIX      # VULN_METADATA_FIX[package:range]="fix_version" (upper bound from range)
VULN_LOOKUP_BUILT=false

# Configuration defaults (can be overridden by config file)
CONFIG_IGNORE_PATHS=("node_modules" ".yarn" ".git")
CONFIG_DEPENDENCY_TYPES=("dependencies" "devDependencies" "optionalDependencies")
CONFIG_ECOSYSTEMS=""  # optional feed-loading override from config (options.ecosystems)

# Ecosystem registry lookup tables — derived from ECOSYSTEM_REGISTRY by
# build_ecosystem_tables() (see src/50-ecosystems/01-registry.sh)
declare -A LOCKFILE_PARSER   # LOCKFILE_PARSER[basename]="analyze_fn"
declare -A LOCKFILE_ECO      # LOCKFILE_ECO[basename]="purl-type"
declare -A LOCKFILE_ALIAS    # LOCKFILE_ALIAS[basename]="type-alias"
KNOWN_LOCKFILE_ALIASES=""    # space-separated unique alias list (validation + help)

# Ecosystems detected in the scanned project (eco -> 1); drives default-feed loading
declare -A DETECTED_ECOSYSTEMS

