# GitHub Advanced Security Reporting Engine - Copilot Instructions

## Project Overview

This is a Go-based CLI tool that generates compliance reports from GitHub Advanced Security (GHAS) findings, mapping them to industry-standard security frameworks (OWASP Top 10 2025, SANS Top 25, MITRE KEV). It produces professional HTML reports.

## Architecture Guidelines

### Core Packages

```text
cmd/ghas-report/main.go        # Cobra CLI entry point
internal/
├── config/config.go            # Configuration struct with Validate()
├── github/client.go            # GitHub REST API client with pagination
├── models/alert.go             # Alert, Rule, Repository types; CWEs() method
├── mapping/mapper.go           # Loads OWASP/SANS/MITRE JSON via //go:embed
│   └── assets/                 # Embedded JSON mapping files
├── analyzer/analyzer.go        # Aggregates alerts into AnalysisResult
├── reporters/
│   ├── html.go                 # WriteHTML() renders reports
│   ├── templates_embed.go      # //go:embed for report.html template
│   └── templates/report.html   # HTML template
├── logging/logging.go          # log/slog setup
└── runtime/runtime.go          # Orchestrates fetch → analyze → report
```

### Technology Stack
- **Language**: Go 1.22+
- **CLI Framework**: `github.com/spf13/cobra`
- **API Client**: `net/http` with JSON decoding & link-header pagination
- **Report Generation**: `html/template` with embedded assets
- **Structured Logging**: `log/slog`
- **Testing**: Standard `testing` package

## Development Guidelines

### Coding Standards

1. **Error Handling**: Always wrap errors with `fmt.Errorf("context: %w", err)`. Never silently discard errors.

   ```go
   resp, err := http.Get(url)
   if err != nil {
       return fmt.Errorf("fetch alerts for %s: %w", repo, err)
   }
   ```

2. **Structured Logging**: Use `log/slog` with key-value pairs.

   ```go
   slog.Info("fetching alerts", "repo", repoName, "state", "open")
   slog.Warn("no CWE mapping found", "cwe", cweID)
   slog.Error("API request failed", "status", resp.StatusCode, "url", url)
   ```

3. **CWE Convention**: CWE IDs are always uppercase `CWE-###`. The `Alert.CWEs()` method extracts them from `Rule.Tags` entries prefixed with `external/cwe/`.

4. **JSON Schema**: Mapping files under `internal/mapping/assets/` use specific schemas:
   - `owasp_top10.json`: `{ "framework", "version", "categories": { "KEY": { "name", "description", "cwes": [] } } }`
   - `sans_top25.json`: `{ "framework", "version", "rankings": [{ "rank", "cwe", "name", "url" }] }`
   - `mitre_kev.json`: `{ "framework", "version", "top_10_kev": [{ "rank", "cwe", "name", "cve_count" }] }`

### Security Considerations
- **Token Management**: Never log or print GitHub tokens. Pass via `--token` flag or `GITHUB_TOKEN` env var.
- **Input Validation**: `config.Validate()` enforces flag invariants before execution.
- **Rate Limiting**: Implement retries with exponential backoff in the HTTP client.

### Testing Requirements
1. **Unit Tests**: Test core logic with the standard `testing` package.
2. **Integration Tests**: `internal/reporters/html_integration_test.go` validates end-to-end report generation.
3. **Mocking**: Mock HTTP responses for GitHub API tests; use `httptest.NewServer`.
4. **Test Files**: Place `_test.go` files alongside the code they test.

```go
func TestCWEsExtraction(t *testing.T) {
    alert := models.Alert{
        Rule: models.Rule{
            Tags: []string{"security", "external/cwe/cwe-089"},
        },
    }
    cwes := alert.CWEs()
    if len(cwes) != 1 || cwes[0] != "CWE-089" {
        t.Errorf("expected [CWE-089], got %v", cwes)
    }
}
```

## CLI Usage

```bash
# Basic organization report
ghas-report --token $GITHUB_TOKEN --organization my-org

# Enterprise report with filters
ghas-report --token $GITHUB_TOKEN --enterprise my-enterprise \
  --report-types owasp,sans,mitre \
  --days-back 90 \
  --severity-filter critical,high \
  --output-dir ./reports

# Use external mapping overrides
ghas-report --token $GITHUB_TOKEN --organization my-org \
  --data-dir ./data/cwe_mappings
```

### CLI Flags (defined in cmd/ghas-report/main.go)

| Flag | Description | Default |
|------|-------------|---------|
| `--token` | GitHub token (env: `GITHUB_TOKEN`) | Required |
| `--organization` | GitHub org name | - |
| `--enterprise` | GitHub enterprise name | - |
| `--report-types` | `owasp,sans,mitre` | `owasp,sans,mitre` |
| `--days-back` | Days to look back (1-365) | `90` |
| `--output-dir` | Report output directory | `./reports` |
| `--log-level` | `DEBUG,INFO,WARN,ERROR` | `INFO` |
| `--include-dismissed` | Include dismissed alerts | `false` |
| `--include-fixed` | Include fixed alerts | `false` |
| `--severity-filter` | Filter by severity | - |
| `--data-dir` | Override mapping data dir | - |
| `--api-base-url` | Override GitHub API URL | `https://api.github.com` |
| `--max-retries` | API retry count | `3` |
| `--request-timeout` | Per-request timeout | `30s` |

## Data Processing Flow

1. **Config & Validate** → `config.Config` parsed from Cobra flags
2. **Fetch Alerts** → `github.Client` paginates code scanning alerts
3. **Extract CWEs** → `Alert.CWEs()` normalizes from `Rule.Tags`
4. **Map to Frameworks** → `mapping.Mapper` loads embedded JSON, matches CWEs
5. **Analyze** → `analyzer.Analyzer` aggregates into `AnalysisResult`
6. **Report** → `reporters.WriteHTML()` renders template per framework

## Common Implementation Tasks

1. **Adding a New Framework**
   - Add JSON mapping file in `internal/mapping/assets/`
   - Add corresponding struct and loader in `internal/mapping/mapper.go`
   - Add analysis method in `internal/analyzer/analyzer.go`
   - Update `config.validReportTypes` in `internal/config/config.go`
   - Add test coverage

2. **Updating Framework Mappings**
   - Edit the JSON in `internal/mapping/assets/` (embedded at compile time)
   - Mirror changes to `data/cwe_mappings/` (external override files)
   - Preserve the JSON schema exactly

3. **Enhancing the HTML Report**
   - Edit `internal/reporters/templates/report.html`
   - Adjust data shaping in `internal/reporters/html.go`
   - Template uses Go `html/template` syntax with a `FuncMap` including `upper`

## Build & Test

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./internal/reporters/

# Build the binary
go build -o ghas-report ./cmd/ghas-report

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o ghas-report_linux_amd64 ./cmd/ghas-report
```
