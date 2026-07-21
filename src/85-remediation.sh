# ============================================================================
# Per-ecosystem remediation snippets for GitHub issue bodies.
#
# The GitHub issue builders in src/90-main.sh used to hardcode npm remediation
# (`npm update` / `npm audit`). These helpers make the "how do I fix this"
# guidance ecosystem-aware so a Cargo, Go, PyPI, … finding gets the command a
# developer on THAT stack would actually run. npm keeps its historical
# update/audit guidance so npm-only issues read essentially as before.
# ============================================================================

# Emit the shell/command lines that fix a vulnerable package, for one ecosystem.
# Args:
#   $1 eco     purl type (npm, cargo, golang, pypi, gem, composer, maven,
#              nuget, pub, hex, swift, githubactions)
#   $2 pkg     package name (or a placeholder like "<package-name>" for the
#              consolidated issue, which is not per-package)
#   $3 indent  optional prefix prepended to every line (e.g. "   " to sit inside
#              a numbered-list code fence). Defaults to no indentation.
# The output is the BODY of a ```bash block; the caller supplies the fence.
fix_commands_for_eco() {
    local eco="$1" pkg="$2" ind="${3:-}"
    case "$eco" in
        npm)
            printf '%snpm update %s\n' "$ind" "$pkg"
            printf '%s# or yarn upgrade %s\n' "$ind" "$pkg"
            printf '%s# or pnpm update %s\n' "$ind" "$pkg"
            printf '%s# auto-fix all advisories: npm audit fix\n' "$ind"
            ;;
        cargo)
            printf '%scargo update -p %s\n' "$ind" "$pkg"
            ;;
        golang)
            printf '%sgo get %s@latest && go mod tidy\n' "$ind" "$pkg"
            ;;
        pypi)
            printf '%spip install --upgrade %s\n' "$ind" "$pkg"
            printf '%s# or with Poetry: poetry update %s\n' "$ind" "$pkg"
            printf '%s# or with uv:     uv lock --upgrade-package %s\n' "$ind" "$pkg"
            ;;
        gem)
            printf '%sbundle update %s\n' "$ind" "$pkg"
            ;;
        composer)
            printf '%scomposer update %s\n' "$ind" "$pkg"
            ;;
        maven)
            printf '%s# Bump %s to the patched version in pom.xml (or build.gradle).\n' "$ind" "$pkg"
            printf '%s# For Gradle lockfiles, refresh them: ./gradlew dependencies --write-locks\n' "$ind"
            ;;
        nuget)
            printf '%sdotnet add package %s\n' "$ind" "$pkg"
            ;;
        pub)
            printf '%sdart pub upgrade %s\n' "$ind" "$pkg"
            ;;
        hex)
            printf '%smix deps.update %s\n' "$ind" "$pkg"
            ;;
        swift)
            printf '%sswift package update %s\n' "$ind" "$pkg"
            ;;
        githubactions)
            printf '%s# Bump the `uses:` ref to the patched tag, e.g. %s@<patched-tag>\n' "$ind" "$pkg"
            ;;
        *)
            printf '%s# Update %s to the latest patched version.\n' "$ind" "$pkg"
            ;;
    esac
}

# Emit the one-line command that re-verifies an ecosystem after updating, used
# as inline code in the issue "Run a security audit" step. Ecosystems without a
# ubiquitous audit tool return a short guidance comment instead.
verify_command_for_eco() {
    case "$1" in
        npm)           echo "npm audit" ;;
        cargo)         echo "cargo audit" ;;
        golang)        echo "govulncheck ./..." ;;
        pypi)          echo "pip-audit" ;;
        gem)           echo "bundle audit" ;;
        composer)      echo "composer audit" ;;
        maven)         echo "# re-run your SCA scan (e.g. OWASP dependency-check, Trivy)" ;;
        nuget)         echo "dotnet list package --vulnerable" ;;
        pub)           echo "dart pub outdated" ;;
        hex)           echo "mix hex.audit" ;;
        swift)         echo "# re-resolve and re-scan Package.resolved" ;;
        githubactions) echo "# re-run package-checker (or pin to the patched commit SHA)" ;;
        *)             echo "# re-run package-checker after updating" ;;
    esac
}

# Human-readable ecosystem label for issue section headings.
eco_display_name() {
    case "$1" in
        npm)           echo "npm / Node.js" ;;
        pypi)          echo "Python (pip / Poetry / uv)" ;;
        golang)        echo "Go modules" ;;
        maven)         echo "Maven / Gradle (JVM)" ;;
        cargo)         echo "Rust (Cargo)" ;;
        gem)           echo "Ruby (Bundler)" ;;
        composer)      echo "PHP (Composer)" ;;
        nuget)         echo "NuGet (.NET)" ;;
        pub)           echo "Dart / Flutter (pub)" ;;
        hex)           echo "Elixir (Hex)" ;;
        swift)         echo "Swift (SwiftPM)" ;;
        githubactions) echo "GitHub Actions" ;;
        *)             echo "$1" ;;
    esac
}
