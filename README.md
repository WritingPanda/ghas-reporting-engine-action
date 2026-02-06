# GHAS Reporting Engine

A Go CLI tool that generates compliance reports from GitHub Advanced Security (GHAS) code scanning alerts, mapping them to industry-standard frameworks like OWASP Top 10 2025, SANS Top 25, and MITRE KEV.

[![Build Status](https://github.com/WritingPanda/ghas-reporting-engine-action/workflows/Build%20and%20Test/badge.svg)](https://github.com/WritingPanda/ghas-reporting-engine-action/actions)
[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multi-Framework Support**: Map GHAS alerts to OWASP Top 10 2025, SANS Top 25, and MITRE KEV
- **HTML Reports**: Generate professional HTML reports per framework
- **Single Binary**: Compile to a single binary with embedded mapping data—no runtime dependencies
- **Flexible Overrides**: Supply custom mapping data via `--data-dir`
- **Enterprise Ready**: Support for both GitHub organizations and enterprises
- **Configurable Filters**: Filter by severity, date range, and alert state

## Quick Start

### Build from Source

```bash
git clone https://github.com/WritingPanda/ghas-reporting-engine-action.git
cd ghas-reporting-engine-action
go build -o ghas-report ./cmd/ghas-report
```

### Run

```bash
# Organization report
./ghas-report \
  --token "$GITHUB_TOKEN" \
  --organization my-org \
  --report-types owasp,sans,mitre

# Enterprise report
./ghas-report \
  --token "$GITHUB_TOKEN" \
  --enterprise my-enterprise \
  --days-back 90 \
  --severity-filter critical,high
```

## Prerequisites

- Go 1.22 or higher
- GitHub Personal Access Token with:
  - `repo` scope for private repositories
  - `security_events` scope for code scanning alerts
  - Organization or enterprise access as needed

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--token` | GitHub token (env: `GITHUB_TOKEN`) | Required |
| `--organization` | GitHub organization name | — |
| `--enterprise` | GitHub enterprise name | — |
| `--report-types` | Comma-separated: `owasp,sans,mitre` | `owasp,sans,mitre` |
| `--days-back` | Days to look back (1–365) | `90` |
| `--output-dir` | Report output directory | `./reports` |
| `--log-level` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` |
| `--include-dismissed` | Include dismissed alerts | `false` |
| `--include-fixed` | Include fixed alerts | `false` |
| `--severity-filter` | Filter: `critical,high,medium,low` | — |
| `--data-dir` | Override mapping data directory | — |
| `--api-base-url` | Override GitHub API URL | `https://api.github.com` |
| `--max-retries` | API retry attempts | `3` |
| `--request-timeout` | Per-request timeout | `30s` |

## Architecture

```text
cmd/ghas-report/main.go          # Cobra CLI entry point
internal/
├── config/config.go              # Configuration & validation
├── github/client.go              # GitHub REST API client with pagination
├── models/alert.go               # Alert, Rule, Repository types
├── mapping/
│   ├── mapper.go                 # Framework mapping logic (//go:embed)
│   └── assets/                   # Embedded JSON mapping data
│       ├── owasp_top10.json
│       ├── sans_top25.json
│       └── mitre_kev.json
├── analyzer/analyzer.go          # Alert aggregation & analysis
├── reporters/
│   ├── html.go                   # HTML report writer
│   ├── templates_embed.go        # //go:embed for template
│   └── templates/report.html     # HTML report template
├── logging/logging.go            # Structured logging (log/slog)
└── runtime/runtime.go            # Orchestrates fetch → analyze → report
data/cwe_mappings/                # External override mapping files
```

### Data Flow

1. **Configure** — Parse CLI flags via Cobra into `config.Config`
2. **Fetch** — `github.Client` paginates code scanning alerts from the GitHub API
3. **Extract CWEs** — `Alert.CWEs()` normalizes CWE IDs from `Rule.Tags` (`external/cwe/*`)
4. **Map** — `mapping.Mapper` matches CWEs against OWASP/SANS/MITRE data
5. **Analyze** — `analyzer.Analyzer` aggregates into `AnalysisResult`
6. **Report** — `reporters.WriteHTML()` renders per-framework HTML reports

## Compliance Frameworks

### OWASP Top 10 2025

Maps alerts to the OWASP Top 10 2025 application security risks including Broken Access Control, Security Misconfiguration, Software Supply Chain Failures, and more.

### SANS Top 25

Maps alerts to the SANS Top 25 Most Dangerous Software Errors, ranked by prevalence and impact.

### MITRE KEV

Maps alerts to MITRE's Top 10 Known Exploited Vulnerabilities, highlighting actively exploited weaknesses.

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./internal/reporters/

# Run a specific test
go test -v -run TestGenerateHTMLReportsForAllFrameworks ./internal/reporters/
```

## GitHub Action Usage

```yaml
name: Security Compliance Report
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  security-report:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build and Run
        run: |
          go build -o ghas-report ./cmd/ghas-report
          ./ghas-report \
            --token "${{ secrets.GITHUB_TOKEN }}" \
            --organization "${{ github.repository_owner }}" \
            --report-types owasp,sans,mitre \
            --days-back 7
```

## Cross-Compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o ghas-report_linux_amd64 ./cmd/ghas-report

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o ghas-report_darwin_arm64 ./cmd/ghas-report

# Windows
GOOS=windows GOARCH=amd64 go build -o ghas-report_windows_amd64.exe ./cmd/ghas-report
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
