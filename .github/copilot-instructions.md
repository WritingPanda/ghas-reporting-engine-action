# GHAS Reporting Engine – AI Guide

## Architecture
- The app is structured as a CLI tool in Go, organized under `ghas-reporting-engine`.

## Data & Frameworks
- Mapping JSON lives in `data/cwe_mappings/` (`owasp_top10.json` → `categories`, `sans_top25.json` → `rankings`, `mitre_kev.json` → `top_10_kev`); keep schemas intact when regenerating.
- `Alert.cwes` derives from `rule.tags` containing `external/cwe/*`; downstream code assumes uppercase `CWE-###`.
- `CWEMapper.get_framework_summary` feeds report metadata; adjust this if you add new fields or frameworks.

## Implementation Patterns
- API interactions use GitHub's API; paginate results for large datasets.
- HTML reports group findings by repository with professional, modern design using templates and CSS.
- Error handling employs precise error types; avoid generic errors and silent catches.
- Logging is structured with context; avoid log spam.

## Testing
- Unit tests cover core logic in `tests/`.
- Mock GitHub API calls to ensure tests are deterministic and fast.
- Validate report generation against sample data in `instructions/sample-output.instructions.json`.