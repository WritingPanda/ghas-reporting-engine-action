# GitHub Advanced Security Reporting Engine - Copilot Instructions

## Project Overview

This is a Python-based application that serves dual purposes:

1. A GitHub Action for automated security reporting in CI/CD pipelines
2. A standalone CLI tool for local report generation

The application pulls CodeQL analysis results from GitHub and maps them to security frameworks (SANS Top 25, OWASP Top 10, MITRE Top 10 KEV), then generates formatted reports in multiple formats, such as JSON, CSV, and HTML.

## Architecture Guidelines

### Core Components

- **Data Fetcher**: Retrieve CodeQL results via GitHub REST/GraphQL API
- **Framework Mapper**: Align CodeQL findings to security frameworks (SANS/OWASP/MITRE)
- **Report Generator**: Create reports in JSON, CSV, and HTML formats
- **CLI Interface**: Click or argparse-based command-line interface
- **GitHub Action Wrapper**: YAML action definition with inputs/outputs

### Technology Stack
- **Language**: Python 3.9+
- **CLI Framework**: Click
- **API Client**: PyGithub or requests + GraphQL
- **Report Generation**: 
  - HTML: Jinja2 templates
  - JSON: Built-in Python
  - CSV: Python `csv` module
- **Configuration**: YAML or JSON for framework mappings
- **Testing**: pytest with fixtures for API mocking

## Code Structure

```
src/ghas_reporting_engine/
├── __init__.py              # Package initialization
├── __main__.py              # Entry point for `python -m` execution
├── cli.py                   # CLI commands and argument parsing
├── config.py                # Configuration management
├── api/                     # GitHub API interaction
│   ├── github_client.py     # API client wrapper
│   └── models.py            # Data models for API responses
├── frameworks/              # Security framework mappings
│   ├── sans_top25.py        # SANS Top 25 mapping logic
│   ├── owasp_top10.py       # OWASP Top 10 mapping logic
│   └── mitre_kev.py         # MITRE KEV mapping logic
├── processors/              # Data processing
│   ├── cwe_mapper.py        # CWE to framework mapping
│   └── data_analyzer.py     # Analysis and statistics
├── reports/                 # Report generation
│   ├── base_reporter.py     # Abstract base class
│   ├── json_reporter.py     # JSON output
│   ├── csv_reporter.py      # CSV output
│   └── html_reporter.py     # HTML output
├── templates/               # Report templates
│   ├── html/                # HTML Jinja2 templates
│   └── css/                 # Stylesheets
└── utils/                   # Helper utilities
    ├── logger.py            # Logging configuration
    ├── validation.py        # Input validation
    └── date_utils.py        # Date/time utilities
```

## Development Guidelines

### Coding Standards
1. **Type Hints**: Always use type hints for function parameters and return values
   ```python
   def fetch_alerts(repo: str, token: str) -> List[CodeQLAlert]:
       pass
   ```

2. **Docstrings**: Use Google-style docstrings for all public functions and classes
   ```python
   def map_cwe_to_sans(cwe_id: str) -> Optional[SANSCategory]:
       """Map a CWE identifier to SANS Top 25 category.
       
       Args:
           cwe_id: The CWE identifier (e.g., "CWE-79")
           
       Returns:
           SANSCategory object if mapping exists, None otherwise
       """
   ```

3. **Error Handling**: Use specific exceptions and provide helpful error messages
   ```python
   class GitHubAPIError(Exception):
       """Raised when GitHub API returns an error."""
       pass
   
   try:
       response = requests.get(url, headers=headers)
       response.raise_for_status()
   except requests.HTTPError as e:
       raise GitHubAPIError(f"Failed to fetch alerts: {e}")
   ```

4. **Logging**: Use structured logging with appropriate levels
   ```python
   logger.info("Fetching alerts for repository", extra={"repo": repo_name})
   logger.warning("No CWE mapping found", extra={"cwe": cwe_id})
   logger.error("API request failed", extra={"status": status_code})
   ```

### Security Considerations
- **Token Management**: Never log or print GitHub tokens
- **Input Validation**: Validate all user inputs and API responses
- **Rate Limiting**: Implement exponential backoff for API calls
- **Secrets**: Use environment variables or GitHub Secrets for sensitive data

### Testing Requirements
1. **Unit Tests**: All core logic must have unit tests with >80% coverage
2. **Integration Tests**: Test GitHub API integration with mocked responses
3. **Fixtures**: Use pytest fixtures for common test data
4. **Mocking**: Mock external API calls using `responses` or `pytest-mock`

```python
# Example test structure
@pytest.fixture
def sample_alert():
    return {
        "number": 1,
        "rule": {"id": "js/sql-injection"},
        "most_recent_instance": {
            "message": {"text": "SQL injection vulnerability"}
        }
    }

def test_cwe_mapping(sample_alert):
    mapper = CWEMapper()
    result = mapper.map_alert(sample_alert)
    assert result.cwe_id == "CWE-89"
```

## GitHub Action Integration

### Action Definition (action.yml)
```yaml
name: 'GHAS Reporting Engine'
description: 'Generate security reports from CodeQL analysis'
inputs:
  github-token:
    description: 'GitHub token with security_events:read scope'
    required: true
  repository:
    description: 'Repository in owner/name format'
    required: false
  frameworks:
    description: 'Comma-separated list: sans,owasp,mitre'
    required: false
    default: 'sans,owasp,mitre'
  output-format:
    description: 'Output format: json,csv,html'
    required: false
    default: 'json,html'
  output-path:
    description: 'Directory for report output'
    required: false
    default: './security-reports'
outputs:
  report-path:
    description: 'Path to generated reports'
  alert-count:
    description: 'Total number of alerts found'
```

### Usage in Workflows
```yaml
steps:
  - name: Generate Security Report
    uses: owner/ghas-reporting-engine@v1
    with:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      frameworks: 'sans,owasp'
      output-format: 'html,json'
```

## CLI Usage Patterns

### Basic Commands
```bash
# Generate report for current repository
ghas-report generate --token $GITHUB_TOKEN

# Specify repository and frameworks
ghas-report generate \
  --repository owner/repo \
  --token $GITHUB_TOKEN \
  --frameworks sans,owasp \
  --format html,json

# Output to specific directory
ghas-report generate \
  --token $GITHUB_TOKEN \
  --output ./reports \
  --format html
```

### CLI Design Principles
- Use subcommands for different operations (`generate`, `validate`, `update-mappings`)
- Provide sensible defaults (current repo, all frameworks, JSON output)
- Support both environment variables and CLI flags for configuration
- Include verbose/debug mode for troubleshooting
- Show progress indicators for long-running operations

## Data Processing Flow

### 1. Alert Retrieval
```python
# Fetch alerts from GitHub API
alerts = github_client.get_code_scanning_alerts(
    owner=owner,
    repo=repo,
    state='open',
    ref=branch
)
```

### 2. CWE Extraction
```python
# Extract CWE from CodeQL rule
for alert in alerts:
    rule_tags = alert.rule.tags
    cwe_id = extract_cwe_from_tags(rule_tags)
    alert.cwe_id = cwe_id
```

### 3. Framework Mapping
```python
# Map CWE to security frameworks
sans_mapping = sans_mapper.map(cwe_id)
owasp_mapping = owasp_mapper.map(cwe_id)
mitre_mapping = mitre_mapper.map(cwe_id)
```

### 4. Report Generation
```python
# Generate reports in requested formats
for format in output_formats:
    reporter = get_reporter(format)
    reporter.generate(
        alerts=enriched_alerts,
        mappings=framework_mappings,
        output_path=output_dir
    )
```

## Configuration Management

### Framework Mapping Files
Store framework mappings in `data/cwe_mappings/`:
- `sans_top25.json`: CWE → SANS Top 25 mappings
- `owasp_top10.json`: CWE → OWASP Top 10 mappings
- `mitre_kev.json`: CWE → MITRE KEV mappings

### Mapping File Format
```json
{
  "framework": "SANS Top 25 2023",
  "version": "1.0",
  "mappings": {
    "CWE-79": {
      "rank": 2,
      "category": "Improper Neutralization of Input During Web Page Generation",
      "severity": "high"
    }
  }
}
```

## Report Output Formats

### JSON Report Structure

```json
{
  "metadata": {
    "repository": "owner/repo",
    "generated_at": "2024-01-15T10:30:00Z",
    "alert_count": 42
  },
  "frameworks": {
    "sans_top25": {
      "total_mapped": 35,
      "categories": [...]
    },
    "owasp_top10": {...},
    "mitre_kev": {...}
  },
  "alerts": [...]
}
```

### HTML Report Features

- Responsive design with mobile support
- Sortable/filterable tables
- Severity-based color coding
- Framework breakdown charts

### CSV Report Columns

```
Alert ID, Rule ID, CWE, Severity, State, Location, SANS Category, OWASP Category, MITRE KEV
```

## Performance Optimization

### API Optimization
- Use GraphQL for complex queries to reduce API calls
- Implement pagination for large result sets
- Cache CodeQL rule metadata
- Batch requests where possible

### Memory Management
- Stream large datasets instead of loading entirely in memory
- Use generators for processing alerts
- Cleanup temporary files after report generation

## Error Handling Patterns

### Graceful Degradation

```python
try:
    sans_mapping = sans_mapper.map(cwe_id)
except MappingNotFoundError:
    logger.warning(f"No SANS mapping for {cwe_id}")
    sans_mapping = None  # Continue with other frameworks
```

### User-Friendly Messages

```python
if not github_token:
    raise ConfigurationError(
        "GitHub token not found. Set GITHUB_TOKEN environment variable "
        "or use --token flag."
    )
```

## Common Implementation Tasks

When implementing new features:

1. **Adding a New Framework**
   - Create `src/ghas_reporting_engine/frameworks/new_framework.py`
   - Add mapping file in `data/cwe_mappings/new_framework.json`
   - Update CLI to include new framework option
   - Add tests in `tests/unit/test_new_framework.py`

2. **Adding a New Report Format**
   - Create `src/ghas_reporting_engine/reports/new_format_reporter.py`
   - Inherit from `BaseReporter`
   - Implement `generate()` method
   - Add template if needed
   - Update CLI format options

3. **Updating Mappings**
   - Provide CLI command: `ghas-report update-mappings --framework sans`
   - Fetch latest framework data from authoritative source
   - Validate mapping structure
   - Update version in mapping file

## Documentation Requirements

- **README.md**: Installation, quick start, usage examples
- **API Documentation**: Auto-generated from docstrings using Sphinx
- **CONTRIBUTING.md**: Development setup, PR guidelines
- **CHANGELOG.md**: Version history and breaking changes
- **Examples**: Sample reports and workflow configurations

## Continuous Integration

### Required CI Checks
- Code formatting (black, isort)
- Linting (flake8, pylint, mypy)
- Unit tests with coverage report
- Integration tests
- Security scanning (bandit, safety)
- Documentation build

### Release Process
1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Tag release: `git tag v1.0.0`
4. Build package: `python -m build`
5. Publish to PyPI: `twine upload dist/*`
6. Create GitHub release with action artifact

## Maintenance Guidelines

- Review and update framework mappings quarterly
- Monitor GitHub API changes and deprecations
- Keep dependencies up to date (dependabot)
- Archive old reports and test fixtures
- Maintain backward compatibility for action inputs

## Quick Reference Commands

# Development setup
uv venv
source venv/bin/activate
uv pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=src/ghas_reporting_engine

# Format code
black src/ tests/
isort src/ tests/

# Type checking
mypy src/

# Build package
uv build

# Run locally
python -m ghas_reporting_engine generate --help
