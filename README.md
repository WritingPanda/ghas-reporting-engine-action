# GHAS Reporting Engine

Generate framework-aligned security reports (OWASP Top 10, SANS Top 25, MITRE KEV Top 10) from GitHub Advanced Security alerts (code scanning, Dependabot, secret scanning). Produces JSON and/or Markdown summaries showing which CWEs & alerts map to each framework, severity breakdowns, and coverage percentages.

## Features

- Parse existing instruction markdown files to build CWE sets per framework
- Map alert CWE(s) (from `rule.cwe`, `rule.id`, tags, supplemental ruleId mapping, Dependabot advisory CWE enrichment) to requested frameworks
- Severity breakdown & coverage (% of framework CWE set represented in alerts)
- Retry with exponential backoff & basic rate limit wait logic
- GitHub Action + local CLI execution
- JSON + Markdown outputs

## Usage (GitHub Action)

### Quick Start (pin to a release tag)

After we publish a release (e.g. `v0.1.0`), prefer pinning:

```yaml
name: Framework Reports
on:
	schedule: [{ cron: '0 3 * * *' }]
	workflow_dispatch: {}

jobs:
	report:
		runs-on: ubuntu-latest
		permissions:
			security-events: read
			contents: read
		steps:
			- uses: actions/checkout@v4
			- name: Generate framework reports
				uses: Pandante-Central/GHAS-Reporting-Engine@v0.1.0
				with:
					frameworks: owasp,sans,kev
					output_format: both   # json | md | both
					include_empty: false
			- name: Upload reports artifact
				uses: actions/upload-artifact@v4
				with:
					name: ghas-framework-reports
						path: reports
```

### Using `main` (latest, potentially unstable)

```yaml
name: Framework Reports (Main)
on:
	workflow_dispatch: {}

jobs:
	report:
		runs-on: ubuntu-latest
		permissions:
			security-events: read
			contents: read
		steps:
			- uses: actions/checkout@v4
			- name: Generate reports (main)
				uses: Pandante-Central/GHAS-Reporting-Engine@main
				with:
					frameworks: owasp,sans,kev
					output_format: both
					include_empty: false
			- name: Upload artifact
				uses: actions/upload-artifact@v4
				with:
					name: ghas-framework-reports
					path: reports
```

### Output
The action writes JSON reports and (if requested) `summary.md`. The markdown is also appended to the GitHub Actions job summary when `output_format` includes `md`.

## Local Run

```bash
npm install
export GITHUB_TOKEN=ghp_yourTokenWithSecurityEventsScope
export OWNER=yourOrg
export REPO=yourRepo
npm run dev --
```

Environment variables accepted (fallback when not in Action):

| Var | Description |
|-----|-------------|
| GITHUB_TOKEN | GitHub token (security_events: read) |
| OWNER / REPO | Repository coordinates (or set GITHUB_REPOSITORY=owner/repo) |
| FRAMEWORKS | Comma list (owasp,sans,kev) |
| SINCE / UNTIL | ISO timestamps to bound created_at |
| OUTPUT_FORMAT | json | md | both |
| INCLUDE_EMPTY | true/false to include frameworks with zero matches |
| MAX_PAGES | Page safety limit (default 50) |
| RETRIES | Retry attempts for transient failures |

Outputs written to `reports/`.

## JSON Report Structure

Framework report (`owasp`, `sans`, `kev`):

```
{
	"type": "owasp",
	"generatedAt": "2025-08-29T...Z",
	"totalAlerts": 42,
	"matchedAlerts": 10,
	"matchedCWEs": 6,
	"totalFrameworkCWEs": 120,
	"severityBreakdown": { "high": 3, "medium": 5, "low": 2 },
	"findings": [ { "alertId": 123, "ruleId": "js/xss", "severity": "high", "cwes": ["CWE-79"] } ],
	"unmatchedFrameworkCWEs": ["CWE-22", "CWE-89", ...]
}
```

Summary report:

```
{
	"type": "summary",
	"generatedAt": "...",
	"totalAlerts": 42,
	"severityBreakdown": { "high": 5, "medium": 30, "low": 7 },
	"findings": [ { "id": 123, "ruleId": "js/xss", "severity": "high", "cwes": ["CWE-79"] } ]
}
```

## Markdown Summary

When `output_format` includes `md`, a `summary.md` is created with a coverage table.

## Development

```bash
npm install
npm test
npm run build
```

## Roadmap

- (Done) Add Dependabot & secret scanning mapping
- Dependabot advisory + nested vulnerability CWE enrichment
- Optional SARIF ingestion
- Caching of framework parse results in dist

## License

MIT