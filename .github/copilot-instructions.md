# GHAS Reporting Engine – AI Guide

## Architecture
- The app is a CLI tool written in Go, built with Cobra (`cmd/ghas-report/main.go`).
- Internal packages live under `internal/`: `config`, `github` (API client), `models`, `mapping`, `analyzer`, `reporters`, `logging`, `runtime`.
- Mapping JSON is embedded via `//go:embed` in `internal/mapping/mapper.go` from `internal/mapping/assets/`.
- External override mapping files live in `data/cwe_mappings/` and can be used via the `--data-dir` flag.

## Data & Frameworks
- `owasp_top10.json` → `categories` map, `sans_top25.json` → `rankings` slice, `mitre_kev.json` → `top_10_kev` slice; keep schemas intact when regenerating.
- `Alert.CWEs()` derives CWE IDs from `Rule.Tags` containing `external/cwe/*`; downstream code assumes uppercase `CWE-###`.
- `Mapper.FrameworkSummaries()` feeds report metadata; adjust this if you add new fields or frameworks.

## Implementation Patterns
- GitHub API interactions use `net/http` with pagination; see `internal/github/client.go`.
- HTML reports use `html/template` with an embedded template (`internal/reporters/templates/report.html`).
- Error handling uses `fmt.Errorf` with `%w` wrapping; avoid generic errors and silent catches.
- Logging uses `log/slog` via structured context; avoid log spam.
- Configuration is handled by `internal/config/config.go` with Cobra flags.

## Testing
- Unit tests use the standard `testing` package; test files live alongside the code they test.
- Integration tests for HTML report generation are in `internal/reporters/html_integration_test.go`.
- Mock GitHub API calls to ensure tests are deterministic and fast.
- Validate report generation against the embedded template and mapping data.