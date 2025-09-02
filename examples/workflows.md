# Example GitHub Workflows

This directory contains example workflows showing different ways to use the GHAS Reporting Engine.

## Basic Weekly Report

```yaml
name: Weekly Security Compliance Report
on:
  schedule:
    - cron: '0 9 * * 1' # Every Monday at 9 AM UTC
  workflow_dispatch:

jobs:
  compliance-report:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: write
    steps:
      - name: Generate GHAS Compliance Report
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          organization: 'your-org-name'
          frameworks: 'owasp,sans,kev'
          output_format: 'markdown'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: weekly-compliance-report-${{ github.run_number }}
          path: reports/
          retention-days: 90
```

## Enterprise Quarterly Report

```yaml
name: Quarterly Enterprise Security Report
on:
  schedule:
    - cron: '0 6 1 */3 *' # First day of every quarter at 6 AM
  workflow_dispatch:
    inputs:
      since_date:
        description: 'Start date (YYYY-MM-DD)'
        required: true
      until_date:
        description: 'End date (YYYY-MM-DD)'
        required: true

jobs:
  enterprise-report:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: write
    steps:
      - name: Generate Enterprise Compliance Report
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          enterprise: 'your-enterprise-name'
          frameworks: 'owasp,sans,kev'
          output_format: 'json'
          include_empty: true
          since_date: ${{ github.event.inputs.since_date }}
          until_date: ${{ github.event.inputs.until_date }}
        env:
          GITHUB_TOKEN: ${{ secrets.ENTERPRISE_TOKEN }}
      
      - name: Process and Send Reports
        run: |
          # Custom script to process JSON reports and send to stakeholders
          python scripts/process_enterprise_reports.py
```

## Critical Applications Focus

```yaml
name: Critical Apps Security Review
on:
  push:
    branches: [main]
    paths:
      - 'critical-apps/**'
  schedule:
    - cron: '0 */6 * * *' # Every 6 hours
  workflow_dispatch:

jobs:
  critical-apps-report:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: read
    steps:
      - name: Focus on Critical Applications
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          organization: 'your-org-name'
          repositories: 'payment-service,user-auth,data-processor,admin-panel'
          frameworks: 'owasp,sans,kev'
          output_format: 'markdown'
          include_empty: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Check for High-Severity Issues
        run: |
          if grep -q "critical\|high" reports/*.md; then
            echo "::error::High-severity security issues found in critical applications"
            exit 1
          fi
```

## Multi-Format Report Generation

```yaml
name: Comprehensive Security Reports
on:
  workflow_dispatch:
    inputs:
      target_org:
        description: 'Organization to scan'
        required: true
      time_period:
        description: 'Time period (days)'
        required: false
        default: '30'

jobs:
  generate-reports:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: write
    strategy:
      matrix:
        format: [markdown, json]
        framework: [owasp, sans, kev]
    steps:
      - name: Generate ${{ matrix.framework }} Report (${{ matrix.format }})
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          organization: ${{ github.event.inputs.target_org }}
          frameworks: ${{ matrix.framework }}
          output_format: ${{ matrix.format }}
          since_date: ${{ steps.calculate-date.outputs.since_date }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload ${{ matrix.framework }} Report
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.framework }}-report-${{ matrix.format }}
          path: reports/
```

## Compliance Dashboard Integration

```yaml
name: Update Compliance Dashboard
on:
  schedule:
    - cron: '0 */4 * * *' # Every 4 hours
  workflow_dispatch:

jobs:
  update-dashboard:
    runs-on: ubuntu-latest
    permissions:
      security-events: read
      contents: read
    steps:
      - name: Generate JSON Reports for Dashboard
        uses: Pandante-Central/GHAS-Reporting-Engine@v1
        with:
          organization: 'your-org-name'
          frameworks: 'owasp,sans,kev'
          output_format: 'json'
          include_empty: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Send to Dashboard API
        run: |
          for report in reports/*.json; do
            curl -X POST \
              -H "Content-Type: application/json" \
              -H "Authorization: Bearer ${{ secrets.DASHBOARD_API_TOKEN }}" \
              -d @"$report" \
              "https://dashboard.example.com/api/compliance/update"
          done
```
