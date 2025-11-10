# GHAS Reporting Engine – AI Guide

## Architecture
- CLI entrypoint `src/ghas_reporting_engine/cli.py:main` orchestrates Config → GitHubClient → DataAnalyzer → format-specific reporters (JSON, CSV, HTML, PDF).
- Config (`config.Config`) is a Pydantic model enforcing report/format enums (including 'pdf'), computing the date window (`since_date`/`until_date`), and naming artifacts via `get_report_path`.
- GitHub Client (`api/github_client.py`) wraps REST calls with retry/backoff, validates the token on init, paginates alerts, and only filters severities after parsing into Pydantic `Alert` instances.
- Data Analyzer (`processors/data_analyzer.py`) builds an `AnalysisResult` using `CWEMapper` to map CWEs, producing summary/repository/trend dictionaries consumed by reporters.
- Reporters extend `reports/base_reporter.BaseReporter`; JSON/CSV/HTML/PDF implementations expect `analysis_result.framework_mappings` keys that mirror `Config.report_types` (`owasp`, `sans`, `mitre`).
- PDF Reporter uses WeasyPrint to convert HTML templates to professional PDF documents with styling and charts.

## Data & Frameworks
- Mapping JSON lives in `data/cwe_mappings/` (`owasp_top10.json` → `categories`, `sans_top25.json` → `rankings`, `mitre_kev.json` → `top_10_kev`); keep schemas intact when regenerating.
- `Alert.cwes` derives from `rule.tags` containing `external/cwe/*`; downstream code assumes uppercase `CWE-###`.
- `CWEMapper.get_framework_summary` feeds report metadata; adjust this if you add new fields or frameworks.

## Implementation Patterns
- Logging flows through `utils/logger` (`setup_logging`, `get_logger`); avoid creating bare `logging.getLogger(__name__)` without the helper.
- Sanitize complex objects for templates and JSON with `utils/json_utils.sanitize_for_json`/`safe_json_dumps`; HTML reporter restores raw CSS after sanitizing context to prevent escaping.
- When adding reporters, use `_get_common_metadata` and honor `Config.get_report_path` so filenames stay consistent with timestamps/targets.
- Framework processors in `frameworks/` carry descriptive copy (summaries, prevention tips)—reuse or extend them instead of re-encoding text elsewhere.
- HTML reports group findings by repository with professional, modern design using Jinja2 templates and CSS.
- PDF reports are generated from HTML templates using WeasyPrint, preserving formatting and charts.

## Developer Workflows
- Package manager: Use `uv` for all dependency management and command execution.
- Install dev tooling: `uv sync --dev` (creates a local `.venv`).
- Match CI checks from `.github/workflows/build-and-test.yml`: `uv run ruff check src/ tests/`, `uv run black --check src/ tests/`, `uv run mypy src/ghas_reporting_engine/`, `uv run pytest` (coverage configured via `pyproject.toml`).
- For CLI smoke tests run `uv run ghas-report --help`; deeper exercises should patch `GitHubClient` in `CliRunner` tests to avoid live API calls.
- Coverage HTML lands in `htmlcov/`; update fixtures under `tests/fixtures/` if analyzer outputs change.

## GitHub Action
- Composite action `.github/actions/ghas-reporting/action.yml` installs the package with `uv sync`, builds command args dynamically, and parses the first JSON report with `jq` for summary outputs.
- PDF reports can be automatically uploaded to Code Scanning when `upload-pdf: true` is set.
- Workflow `build-and-test.yml` runs on Python 3.11/3.12 using `uv` for all operations; align new tooling or test targets with that matrix.

## Gotchas
- Enterprise support currently stubs `_fetch_enterprise_via_orgs` (returns `[]`); call this out if you plan to rely on enterprise data.
- `Config.report_types`/`report_formats` validators must be updated alongside CLI help strings when introducing new variants (currently supports json, csv, html, pdf).
- CLI uses `rich.Progress`; retain friendly status text when restructuring output so composite action logs stay readable.
- PDF generation requires WeasyPrint and system dependencies (Cairo, Pango); ensure these are available in CI environments.
