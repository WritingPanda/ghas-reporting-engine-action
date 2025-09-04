# GHAS Reporting Engine

A comprehensive GitHub Action that generates compliance reports from GitHub Advanced Security (GHAS) CodeQL alerts, mapping them to industry-standard security frameworks including OWASP Top 10, SANS Top 25, and MITRE Top 10 KEV (Known Exploited Vulnerabilities).

## Features

- 🛡️ **Multi-Framework Support**: Generate reports aligned with OWASP Top 10 2021, SANS Top 25, and MITRE Top 10 KEV
- 🏢 **Organization & Enterprise Support**: Scan entire organizations or enterprises
- 📊 **Multiple Output Formats**: Generate reports in Markdown or JSON format
- 🎯 **Smart CWE Mapping**: Automatically extracts and maps CWE identifiers from CodeQL alerts
- 📅 **Date Filtering**: Focus on specific time periods for compliance reporting
- 🔍 **Repository Filtering**: Target specific repositories within your organization
- 📈 **Comprehensive Analytics**: Detailed breakdowns with severity analysis and recommendations
- ⚡ **GitHub Actions Integration**: Runs seamlessly in your CI/CD workflows

## Quick Start

### Basic Usage

```yaml
name: Security Compliance Report
on:
  schedule:
    - cron: '0 9 * * 1' # Weekly on Monday at 9 AM
  workflow_dispatch:

jobs:
  compliance-report:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: read
    steps:
      - name: Generate GHAS Compliance Report
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          organization: 'your-org-name'
          frameworks: 'owasp,sans,kev'
          output_format: 'markdown'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Advanced Configuration

```yaml
- name: Generate Detailed Compliance Report
  uses: Pandante-Central/GHAS-Reporting-Engine@v1
  with:
    organization: 'your-org-name'
    frameworks: 'owasp,sans,kev'
    output_format: 'json'
    include_empty: true
    since_date: '2024-01-01'
    until_date: '2024-12-31'
    repositories: 'critical-app,payment-service'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `token` | GitHub token with security_events:read permissions | No | `${{ github.token }}` |
| `organization` | GitHub organization to scan (mutually exclusive with enterprise) | No | - |
| `enterprise` | GitHub enterprise to scan (mutually exclusive with organization) | No | - |
| `frameworks` | Comma-separated list of frameworks (owasp, sans, kev) | No | `owasp,sans,kev` |
| `output_format` | Output format for reports (markdown, json) | No | `markdown` |
| `include_empty` | Include categories with zero alerts | No | `false` |
| `since_date` | Only include alerts after this date (YYYY-MM-DD) | No | - |
| `until_date` | Only include alerts before this date (YYYY-MM-DD) | No | - |
| `repositories` | Comma-separated list of specific repositories to scan | No | - |

## Outputs

| Output | Description |
|--------|-------------|
| `reports_generated` | Number of reports generated |
| `report_summary` | Summary of the generated reports |

## Supported Frameworks

### OWASP Top 10 2021

Maps CodeQL alerts to the latest OWASP Top 10 categories:

- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

### SANS Top 25

Aligns with the SANS Top 25 Most Dangerous Software Errors:

- CWE-787: Out-of-bounds Write
- CWE-79: Cross-site Scripting
- CWE-89: SQL Injection
- CWE-416: Use After Free
- And 21 more critical weakness types

### MITRE Top 10 KEV

Maps to MITRE's Top 10 Known Exploited Vulnerabilities:

- CWE-787: Out-of-bounds Write (Score: 75.59)
- CWE-843: Type Confusion (Score: 24.91)
- CWE-78: OS Command Injection (Score: 24.27)
- And 7 more high-impact vulnerabilities

## Permissions Required

The action requires the following permissions:

```yaml
permissions:
  security-events: read  # To access CodeQL alerts
  contents: read        # To read repository information
```

For enterprise scanning, additional permissions may be required.

## Report Structure

### Markdown Reports

- Executive summary with key metrics
- Framework-specific analysis with detailed breakdowns
- Alert distribution by severity
- Repository impact analysis
- Actionable recommendations

### JSON Reports

- Machine-readable format for integration with other tools
- Complete alert details with CWE mappings
- Structured data for dashboards and analytics

## Example Report Output

```markdown
# OWASP Top 10 2021 Compliance Report

**Generated:** 2024-01-15 10:30:00
**Target:** Organization: acme-corp
**Repositories Scanned:** 45

## Executive Summary

- **Total CodeQL Alerts:** 127
- **Repositories Scanned:** 45
- **Alerts Mapped to Framework:** 98
- **Unmapped Alerts:** 29
- **Coverage:** 77%

## OWASP Top 10 2021 Analysis

### Summary by Category

| Category | Alert Count | CWEs |
|----------|-------------|------|
| A03:2021 - Injection | 34 | CWE-79, CWE-89, CWE-78 |
| A01:2021 - Broken Access Control | 28 | CWE-22, CWE-862, CWE-863 |
| A07:2021 - Identification and Authentication Failures | 15 | CWE-287, CWE-306 |
```

## Development

### Building the Action

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Bundle for distribution
npm run bundle

# Run tests
npm test
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm test -- --coverage
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/Pandante-Central/GHAS-Reporting-Engine/wiki)
- 🐛 [Issues](https://github.com/Pandante-Central/GHAS-Reporting-Engine/issues)
- 💬 [Discussions](https://github.com/Pandante-Central/GHAS-Reporting-Engine/discussions)

## Security

If you discover a security vulnerability, please send an email to <writingpanda@github.com>. All security vulnerabilities will be promptly addressed.

---

Made with 🐼 by the Field Security Specialists team.
