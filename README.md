# GHAS Reporting Engine

A powerful CLI tool and GitHub Action that generates compliance reports from GitHub Advanced Security (GHAS) findings, mapping them to industry-standard frameworks like OWASP Top 10, SANS Top 25, and MITRE KEV.

[![Build Status](https://github.com/WritingPanda/ghas-reporting-engine-action/workflows/Build%20and%20Test/badge.svg)](https://github.com/WritingPanda/ghas-reporting-engine-action/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- **Multi-Framework Support**: Map GHAS alerts to OWASP Top 10 2021, SANS Top 25, and MITRE KEV
- **Multiple Output Formats**: Generate reports in JSON, CSV, and interactive HTML formats
- **GitHub Action Integration**: Run as part of your CI/CD pipeline
- **Comprehensive Analysis**: Detailed insights, trends, and recommendations
- **Rich Visualizations**: Interactive charts and graphs in HTML reports
- **Flexible Filtering**: Filter by severity, date range, and alert state
- **Enterprise Ready**: Support for both GitHub organizations and enterprises

## 🚀 Quick Start

### As a CLI Tool

```bash
# Install the package
pip install ghas-reporting-engine

# Generate OWASP Top 10 and SANS Top 25 reports for your organization
ghas-report \
  --token $GITHUB_TOKEN \
  --organization your-org \
  --report-types owasp,sans \
  --report-formats html,json \
  --days-back 30
```

### As a GitHub Action

```yaml
name: Security Compliance Report
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday at 9 AM
  workflow_dispatch:

jobs:
  security-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate GHAS Compliance Report
        uses: WritingPanda/ghas-reporting-engine-action/.github/actions/ghas-reporting@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          organization: ${{ github.repository_owner }}
          report-types: 'owasp,sans,mitre'
          report-formats: 'html,json,csv'
          days-back: '30'
```

## 📋 Prerequisites

- Python 3.11 or higher
- GitHub Personal Access Token with appropriate permissions:
  - `repo` scope for private repositories
  - `security_events` scope for code scanning alerts
  - Organization or enterprise access as needed

## 🛠️ Installation

### From PyPI (Recommended)

```bash
pip install ghas-reporting-engine
```

### From Source

```bash
git clone https://github.com/WritingPanda/ghas-reporting-engine-action.git
cd ghas-reporting-engine-action
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/WritingPanda/ghas-reporting-engine-action.git
cd ghas-reporting-engine-action
pip install -e ".[dev]"
```

## 📖 Usage

### Command Line Interface

#### Basic Usage

```bash
# Organization report
ghas-report --token $GITHUB_TOKEN --organization my-org

# Enterprise report
ghas-report --token $GITHUB_TOKEN --enterprise my-enterprise
```

#### Advanced Usage

```bash
ghas-report \
  --token $GITHUB_TOKEN \
  --organization my-org \
  --report-types owasp,sans,mitre \
  --report-formats json,csv,html \
  --days-back 90 \
  --output-dir ./security-reports \
  --include-dismissed \
  --severity-filter critical,high \
  --log-level DEBUG
```

#### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--token` | GitHub token (or set `GITHUB_TOKEN` env var) | Required |
| `--organization` | GitHub organization name | None |
| `--enterprise` | GitHub enterprise name | None |
| `--report-types` | Comma-separated: `owasp,sans,mitre` | `owasp,sans,mitre` |
| `--report-formats` | Comma-separated: `json,csv,html` | `json,html` |
| `--days-back` | Number of days to look back (1-365) | `30` |
| `--output-dir` | Output directory for reports | `./reports` |
| `--include-dismissed` | Include dismissed alerts | `False` |
| `--severity-filter` | Filter by severity levels | None |
| `--log-level` | Logging level | `INFO` |

### GitHub Action

#### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for API access | ✅ | |
| `organization` | GitHub organization name | | |
| `enterprise` | GitHub enterprise name | | |
| `report-types` | Report types to generate | | `owasp,sans,mitre` |
| `report-formats` | Output formats | | `json,html` |
| `days-back` | Days to look back | | `30` |
| `output-path` | Output path for reports | | `./reports` |
| `include-dismissed` | Include dismissed alerts | | `false` |
| `severity-filter` | Severity filter | | |

#### Outputs

| Output | Description |
|--------|-------------|
| `reports-path` | Path to generated reports |
| `summary` | Brief analysis summary |
| `total-alerts` | Total number of alerts |
| `mapped-alerts` | Alerts mapped to frameworks |

#### Example Workflows

**Weekly Security Report**

```yaml
name: Weekly Security Report
on:
  schedule:
    - cron: '0 9 * * 1'

jobs:
  security-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate Security Report
        uses: WritingPanda/ghas-reporting-engine-action/.github/actions/ghas-reporting@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          organization: ${{ github.repository_owner }}
          report-types: 'owasp,sans'
          days-back: '7'
```

**Pull Request Security Check**

```yaml
name: PR Security Check
on:
  pull_request:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate Security Report
        uses: WritingPanda/ghas-reporting-engine-action/.github/actions/ghas-reporting@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          organization: ${{ github.repository_owner }}
          report-types: 'mitre'
          report-formats: 'json'
          days-back: '30'
          severity-filter: 'critical,high'
```

## 📊 Report Formats

### JSON Reports

Structured data perfect for integration with other tools and systems.

```json
{
  "framework": "OWASP Top 10 2021",
  "total_alerts": 150,
  "mapped_alerts": 120,
  "categories": {
    "A01:2021 - Broken Access Control": 45,
    "A03:2021 - Injection": 38
  },
  "recommendations": [...]
}
```

### CSV Reports

Tabular data ideal for spreadsheet analysis and reporting.

| OWASP_Category | Alert_Count | Risk_Level |
|----------------|-------------|------------|
| A01:2021 - Broken Access Control | 45 | High |
| A03:2021 - Injection | 38 | High |

### HTML Reports

Rich, interactive reports with visualizations and detailed analysis.

- Executive summary with key metrics
- Interactive charts and graphs
- Detailed CWE analysis tables
- Repository breakdown
- Actionable recommendations

## 🔍 Compliance Frameworks

### OWASP Top 10 2021

Maps alerts to the OWASP Top 10 application security risks:

- A01:2021 – Broken Access Control
- A02:2021 – Cryptographic Failures
- A03:2021 – Injection
- And 7 more categories...

### SANS Top 25

Maps alerts to the SANS Top 25 Most Dangerous Software Errors, ranked by prevalence and impact.

### MITRE KEV

Maps alerts to MITRE's Top 10 Known Exploited Vulnerabilities, highlighting actively exploited weaknesses.

## 🏗️ Architecture

```
src/ghas_reporting_engine/
├── cli.py              # Command-line interface
├── config.py           # Configuration management
├── api/
│   ├── github_client.py # GitHub API client
│   └── models.py       # Data models
├── processors/
│   ├── data_analyzer.py # Core analysis engine
│   └── cwe_mapper.py   # CWE to framework mapping
├── frameworks/
│   ├── owasp_top10.py  # OWASP-specific processing
│   ├── sans_top25.py   # SANS-specific processing
│   └── mitre_kev.py    # MITRE KEV processing
├── reports/
│   ├── json_reporter.py # JSON report generation
│   ├── csv_reporter.py  # CSV report generation
│   └── html_reporter.py # HTML report generation
└── templates/          # HTML templates and assets
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/ghas_reporting_engine

# Run specific test file
pytest tests/unit/test_cli.py -v

# Run integration tests
pytest tests/integration/ -v
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/WritingPanda/ghas-reporting-engine-action.git
cd ghas-reporting-engine-action

# Install development dependencies
pip install -e ".[dev]"

# Run pre-commit hooks
pre-commit install

# Run tests
pytest
```

### Code Quality

We use several tools to maintain code quality:

- **Black**: Code formatting
- **Ruff**: Linting and code analysis
- **MyPy**: Type checking
- **Pytest**: Testing framework

## 📚 Examples

### Analyzing a Large Organization

```bash
ghas-report \
  --token $GITHUB_TOKEN \
  --organization microsoft \
  --report-types owasp,sans,mitre \
  --days-back 90 \
  --severity-filter critical,high \
  --output-dir ./microsoft-security-report
```

### Enterprise Security Dashboard

```bash
ghas-report \
  --token $GITHUB_TOKEN \
  --enterprise my-enterprise \
  --report-formats html \
  --days-back 30 \
  --include-dismissed \
  --output-dir ./enterprise-dashboard
```

### Continuous Monitoring

Set up GitHub Actions to run weekly reports and track security posture over time.

## 🔧 Configuration

### Environment Variables

```bash
# Required
export GITHUB_TOKEN="your_token_here"

# Optional
export LOG_LEVEL="INFO"
export OUTPUT_DIR="./reports"
export REQUEST_TIMEOUT="30"
export MAX_RETRIES="3"
```

### Configuration File

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
# Edit .env with your settings
```

## 🚨 Troubleshooting

### Common Issues

**Authentication Errors**

- Verify your GitHub token has the correct scopes
- Check token expiration
- Ensure access to the target organization/enterprise

**Rate Limiting**

- The tool automatically handles GitHub API rate limits
- For large organizations, consider running during off-peak hours

**Permission Errors**

- Ensure your token has `security_events` scope
- Verify organization/enterprise membership and permissions

**Memory Issues**

- For very large datasets, consider filtering by date range or severity
- Run reports for smaller time periods

### Debug Mode

```bash
ghas-report --log-level DEBUG --organization my-org
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- GitHub for the Advanced Security APIs
- OWASP for the Top 10 framework
- SANS for the Top 25 CWE list
- MITRE for the KEV catalog
- The security community for their contributions

## 📞 Support

- 🐛 [Report bugs](https://github.com/WritingPanda/ghas-reporting-engine-action/issues)
- 💡 [Request features](https://github.com/WritingPanda/ghas-reporting-engine-action/issues)
- 📖 [Documentation](https://github.com/WritingPanda/ghas-reporting-engine-action/wiki)
- 💬 [Discussions](https://github.com/WritingPanda/ghas-reporting-engine-action/discussions)

---

**Made with ❤️ for the security community**
