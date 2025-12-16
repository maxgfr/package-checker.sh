## [1.3.3](https://github.com/maxgfr/package-checker.sh/compare/v1.3.2...v1.3.3) (2025-12-16)

### Bug Fixes

* update vulnerability feeds - 2025-12-16 21:28:19 UTC ([a01f110](https://github.com/maxgfr/package-checker.sh/commit/a01f110448be9fcaaecdeca663319e521d2e56a3))

## [1.3.2](https://github.com/maxgfr/package-checker.sh/compare/v1.3.1...v1.3.2) (2025-12-16)

### Documentation

* update README to improve command-line options section and export examples ([5e2461a](https://github.com/maxgfr/package-checker.sh/commit/5e2461a7c8415b08ce14458897260e13f603e8ea))

## [1.3.1](https://github.com/maxgfr/package-checker.sh/compare/v1.3.0...v1.3.1) (2025-12-16)

### Bug Fixes

* enhance CI/CD integration with reusable workflows and local feed usage examples ([fa85e28](https://github.com/maxgfr/package-checker.sh/commit/fa85e283e46501bd09393d51b15bd92a33dc3d3e))
* update vulnerability feeds - 2025-12-16 20:43:23 UTC ([01e66d1](https://github.com/maxgfr/package-checker.sh/commit/01e66d1a05763fd7032076410940697b1f4b7c12))

## [1.3.0](https://github.com/maxgfr/package-checker.sh/compare/v1.2.4...v1.3.0) (2025-12-16)

### Features

* add examples for using built-in GHSA and OSV feeds in workflows ([eec9bff](https://github.com/maxgfr/package-checker.sh/commit/eec9bff1fd6b193cc8e03b17fe44703613ae6ef1))

## [1.2.4](https://github.com/maxgfr/package-checker.sh/compare/v1.2.3...v1.2.4) (2025-12-16)

### Bug Fixes

* enhance vulnerability feed update process with retry logic for git push ([c915130](https://github.com/maxgfr/package-checker.sh/commit/c9151301602fcacfb9d65627484b1b892df0234c))

## [1.2.3](https://github.com/maxgfr/package-checker.sh/compare/v1.2.2...v1.2.3) (2025-12-16)

### Bug Fixes

* update script command for fetching all feeds and enhance Docker image size details in documentation ([ffb723c](https://github.com/maxgfr/package-checker.sh/commit/ffb723c3472483bb6e633c90a6b6bdea6d42d4f9))

## [1.2.2](https://github.com/maxgfr/package-checker.sh/compare/v1.2.1...v1.2.2) (2025-12-16)

### Bug Fixes

* update Docker image sizes in documentation and workflows; enhance descriptions for clarity ([5cb82ff](https://github.com/maxgfr/package-checker.sh/commit/5cb82ffb856d12bf304b90cc593a532c7abb81fb))

## [1.2.1](https://github.com/maxgfr/package-checker.sh/compare/v1.2.0...v1.2.1) (2025-12-16)

### Bug Fixes

* update Dockerfiles to use Alpine 3.19; enhance README for one-click install and run options ([9f256c8](https://github.com/maxgfr/package-checker.sh/commit/9f256c8460f6fbd20eb6f9dc08f2aa232557baef))

## [1.2.0](https://github.com/maxgfr/package-checker.sh/compare/v1.1.0...v1.2.0) (2025-12-16)

### Features

* update Dockerfiles to improve build process and add workspace directory; refactor dependency installation ([d5d3695](https://github.com/maxgfr/package-checker.sh/commit/d5d369554ea01c03551de459e674d8f1de44214e))

## [1.1.0](https://github.com/maxgfr/package-checker.sh/compare/v1.0.0...v1.1.0) (2025-12-16)

### Features

* update Dockerfiles to set bash as the default shell and avoid post-install script issues ([e8d4462](https://github.com/maxgfr/package-checker.sh/commit/e8d44625cccfdc0c8914ca4076f29e60892d4170))

## 1.0.0 (2025-12-16)

### Features

* add direct package lookup functionality and enhance documentation ([f920dbf](https://github.com/maxgfr/package-checker.sh/commit/f920dbfefafe09f33afd13767518e06b6f3b1b08))
* add JSON and CSV sources to package-checker configuration ([9953147](https://github.com/maxgfr/package-checker.sh/commit/995314781c5ff5c7bd03ffd003dc7e737cef71aa))
* add normalization for multi-line CSV values in parsing functions ([4bac523](https://github.com/maxgfr/package-checker.sh/commit/4bac523a534b347df59deba6f09674a91504795c))
* Add package.json for Next.js project with dependencies and scripts ([9dfd2e9](https://github.com/maxgfr/package-checker.sh/commit/9dfd2e9662a67bdf74f95a8477b86f94fb928c04))
* add README, configuration, example vulnerability files, and main script ([2b2aa9b](https://github.com/maxgfr/package-checker.sh/commit/2b2aa9b12de7b5e327d9eb5dfd529becb557a374))
* add support for automatically creating GitHub issues for vulnerable repositories ([ef63c84](https://github.com/maxgfr/package-checker.sh/commit/ef63c849f7d7571938ea07b4486c87f6d97fcf53))
* add support for custom CSV columns in script and update README examples ([be266ca](https://github.com/maxgfr/package-checker.sh/commit/be266cac657db83b8aff9610ca2791efdcf8059b))
* add support for PURL format in vulnerability checker and update documentation ([fe4ca6e](https://github.com/maxgfr/package-checker.sh/commit/fe4ca6e84e3741e6f50c5ac75aa6a8877722a4b3))
* add test code structure for improved readability and maintainability ([614defb](https://github.com/maxgfr/package-checker.sh/commit/614defb878055f6074e4a0926c7b9c9d9f79a08b))
* enhance GitHub API request handling with automatic retry on rate limit and optimize repository counting ([cf19a41](https://github.com/maxgfr/package-checker.sh/commit/cf19a4121417d838b43492672bf8484e48cbc30a))
* enhance JSON parsing functions for improved key extraction and object merging ([2cb9371](https://github.com/maxgfr/package-checker.sh/commit/2cb937106a3edcb861e7ab5952e61bee33c4ca1f))
* Enhance package-checker.sh to support additional vulnerability report formats ([6699889](https://github.com/maxgfr/package-checker.sh/commit/66998898ab089c01053588ec933792fcb620d6e6))
* enhance workflow examples and improve test reporting for package checker ([4855b9c](https://github.com/maxgfr/package-checker.sh/commit/4855b9ce5e7df74e09490456e0a7826f82930dd8))
* migrate configuration to .package-checker.config.json and update README ([327e6cb](https://github.com/maxgfr/package-checker.sh/commit/327e6cb8dd064738d87849b7ee61a0a5ae294b9d))
* optimize GitHub repository fetching and path extraction for improved performance ([74ffa7d](https://github.com/maxgfr/package-checker.sh/commit/74ffa7df241dfc555110a0ab0177cbd6d42c4096))
* optimize JSON object length calculation for improved performance ([c48cad9](https://github.com/maxgfr/package-checker.sh/commit/c48cad9e79fd85ab96edac908e829d98ef103c4e))
* Refactor vulnerability data format in CSV, JSON, and PURL files; add severity and CVE details for Next.js vulnerabilities; introduce new CSV file for additional package vulnerabilities. ([8bbbf54](https://github.com/maxgfr/package-checker.sh/commit/8bbbf544082e2c1e4ee99858488011cfd2fde7b0))
* update configuration to include additional vulnerability sources and performance comparison ([70e5646](https://github.com/maxgfr/package-checker.sh/commit/70e5646b67b0fa56478e2eab3fc9a6626e7311aa))
* update Dockerfiles to use latest Alpine version and introduce VERSION ARG for dynamic versioning ([198d0b7](https://github.com/maxgfr/package-checker.sh/commit/198d0b76a8d615db5c1a94769cca981f25d8ef1c))
* update documentation and add reusable workflow examples for GitHub Actions ([9c901da](https://github.com/maxgfr/package-checker.sh/commit/9c901da1e640b787f8474f61e981eaa6e1c7403a))

### Bug Fixes

* correct installation command for Trivy in documentation ([4be9faa](https://github.com/maxgfr/package-checker.sh/commit/4be9faa57363a3f08839b95466fcdc242aa4f8ae))
* correct path to package-checker script in workflow and update README for package manager support ([74b700c](https://github.com/maxgfr/package-checker.sh/commit/74b700c6444b8110513e6cad7312cc231aca0f0e))
* **docs:** add direct execution examples for script usage in README ([f392c3d](https://github.com/maxgfr/package-checker.sh/commit/f392c3dea973621a017b29c0c12c0a9f7c53a717))
* increase perf ([a5e37ef](https://github.com/maxgfr/package-checker.sh/commit/a5e37efe9b2c885d973ca7ff63c72f3056032938))
* standardize formatting in workflow YAML files for consistency ([211037a](https://github.com/maxgfr/package-checker.sh/commit/211037ac2313da0ee870b6e70a84eb69472363a3))
* update script download URLs to use correct GitHub repository path ([0b75b2a](https://github.com/maxgfr/package-checker.sh/commit/0b75b2a65233a4c03b46ff58617f1d7039fca5e1))
* update vulnerability fields to package_versions and package_versions_range for consistency ([23b6bd3](https://github.com/maxgfr/package-checker.sh/commit/23b6bd34e995acd0b97dbe621be09fd6dcf96157))

### Code Refactoring

* code structure for improved readability and maintainability ([1a37859](https://github.com/maxgfr/package-checker.sh/commit/1a37859adfc06bab7cec69df74eedf9e27a4528b))
* code structure for improved readability and maintainability ([471f334](https://github.com/maxgfr/package-checker.sh/commit/471f3346407a5fdcfc279b94119d319ef6867d6c))

# Changelog

All notable changes to this project will be documented in this file. See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [Unreleased]

### Features

- Built-in GHSA and OSV vulnerability feeds with 200,000+ npm vulnerabilities
- Docker images: full version (~43MB) and lightweight version (~27MB)
- Support for SARIF, SBOM (CycloneDX), and Trivy JSON formats
- Direct package lookup without project scanning
- GitHub organization scanning with automatic issue creation
- Multi-source vulnerability scanning
- Automated versioning and releases via Conventional Commits
- Comprehensive documentation for Docker, CI/CD, and contributing

### Documentation

- Added Docker usage guide
- Updated all documentation for built-in vulnerability feeds
- Added contributing guide with versioning workflow
- Updated CI/CD examples for Docker and built-in feeds
