# code-scanning-codeql

A collection of CodeQL code-scanning examples, configurations, and guidance for analyzing Python projects with CodeQL. Use this repository as a reference for setting up CodeQL locally and in CI (GitHub Actions), writing and running CodeQL queries, and integrating code-scanning into your development workflow.

## Contents
- Overview and purpose
- Quick start (local & CI)
- Recommended repository layout
- Example GitHub Actions workflow for CodeQL
- Running CodeQL locally
- Writing and running custom queries
- Contributing
- License & contacts

> Note: This README is written generically for a Python-focused CodeQL code-scanning repository. Adjust paths, filenames, and examples to match your repository structure.

## Overview
This repository demonstrates how to configure and run CodeQL code scanning for Python projects. It includes examples for:
- Using the CodeQL CLI to analyze a codebase
- Running CodeQL via GitHub Actions
- Organizing custom CodeQL queries for Python
- Best practices for continuous scanning and triage

## Requirements
- Python project (this repo is Python-focused)
- CodeQL CLI (installable from GitHub or via package managers)
- Git (for local analysis)
- GitHub repository with Actions enabled (for CI runs)

## Quick start — GitHub Actions (recommended)
Add a workflow at .github/workflows/codeql-analysis.yml (example below) to enable automatic code scanning on push and PRs.

Example workflow:
```yaml
name: "CodeQL"
on:
  push:
    branches: [ main ]
  pull_request:
    paths: [ '**.py' ]

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python

      - name: Autobuild (optional)
        uses: github/codeql-action/autobuild@v3

      - name: Run CodeQL analysis
        uses: github/codeql-action/analyze@v3
```

Adjust branches and path filters as needed. For private queries or custom packs, add them and configure the `init` step accordingly.

## Running CodeQL locally
1. Install CodeQL CLI:
   - Download from https://github.com/github/codeql-cli-binaries or follow official instructions.
2. Create a CodeQL database for the Python code:
   - cd to repository root
   - codeql database create codeql-db --language=python --command="python -m build"  
     (or substitute an appropriate build/prep command)
3. Run queries against the database:
   - codeql database analyze codeql-db path/to/queries --format=sarifv2.1.0 --output=results.sarif

Example minimal commands:
```bash
# create DB (use proper build or environment setup command)
codeql database create codeql-db --language=python --command="python -m pip install -r requirements.txt"

# run default queries shipped with CodeQL
codeql database analyze codeql-db --format=sarifv2.1.0 --output=codeql-results.sarif

# run a custom query or query pack
codeql database analyze codeql-db /path/to/custom-queries --format=sarifv2.1.0 --output=custom-results.sarif
```

## Writing custom CodeQL queries (Python)
- Place custom queries in a pack layout, e.g., a directory `ql/custom-python-queries`.
- Each query file uses QL language and the Python CodeQL libraries.
- Example structure:
  - ql/
    - pack.yml
    - queries/
      - my-query.ql
      - my-query-test.ql
- Use `codeql pack` tools and `codeql database analyze` to run your queries.
- Add tests for queries when possible to validate correctness.

## Repository layout (suggested)
- .github/
  - workflows/
    - codeql-analysis.yml
- ql/
  - pack.yml
  - queries/
- scripts/ (helper scripts for local analysis)
- docs/ (how-tos and guidance)
- examples/ (small sample Python projects for testing queries)

## Interpreting results
- CodeQL outputs SARIF files usable by GitHub or local SARIF viewers.
- On GitHub, results are shown under Security -> Code scanning alerts.
- For local triage, use SARIF viewers or convert to other formats as needed.

## Best practices
- Run CodeQL in CI on pushes and PRs targeting main branches.
- Customize query packs to reduce noise and focus on relevant checks.
- Keep dependencies and environment reproducible for consistent analysis.
- Triage and suppress false positives via documented rationale and, if needed, ignore rules in code or query metadata.

## Contributing
- Fork the repository and make changes on feature branches.
- Add tests for new queries and validate them against example projects.
- Document any workflow changes in docs/.
- Open a pull request describing the change and include reproductions for query behavior if relevant.

## License
Specify a license for the repository (e.g., MIT, Apache-2.0). If no license is present, add one to clarify reuse and contributions.

## Contact / Support
- For questions about CodeQL and queries, consult the official CodeQL docs: https://codeql.github.com/docs/
- If this repository is maintained by a team, add a maintainer contact or issue template.
