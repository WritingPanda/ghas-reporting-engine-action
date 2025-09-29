# GHAS Reporting Engine

A TypeScript application that generates compliance reports from GitHub Advanced Security (GHAS) findings, mapping CodeQL alerts to compliance frameworks like OWASP Top 10, SANS Top 25, and MITRE KEV.

## 🚧 Current Status - Phase 1 Complete: CLI Interface Ready

This project has completed **Phase 1** with a fully functional CLI interface for generating security compliance reports from GitHub Advanced Security findings.

### ✅ Completed in Phase 1

- **Project scaffolding** with TypeScript configuration
- **Type definitions** for GitHub API responses and internal data structures  
- **GitHub API client** with pagination support for fetching CodeQL alerts
- **CWE extraction utilities** for processing alert rule tags
- **CLI interface** with comprehensive argument parsing and validation
- **Multi-format output** support (JSON, Markdown, HTML)
- **Time-based filtering** with flexible date range options
- **Logging infrastructure** with configurable log levels
- **GitHub Actions integration** support
- **Unit tests** for core functionality
- **ESLint configuration** for code quality

## 📋 CLI Usage

### Basic Usage

```bash
# Generate a JSON report for an organization
npm run cli -- --target my-org --frameworks owasp-top-10 --output json

# Generate a markdown report for the last 30 days
npm run cli -- --target my-org --days 30 --output markdown --output-file report.md

# Generate an HTML report with all frameworks
npm run cli -- --target my-org --frameworks owasp-top-10,mitre-top-10-kev,sans-top-25 --output html

# Use with custom GitHub Enterprise
npm run cli -- --target my-org --github-url https://github.enterprise.com/api/v3 --frameworks sans-top-25
```

### CLI Options

```bash
Usage: ghas-reporting-engine [options]

Options:
  -t, --target <name>            target organization or enterprise name (required)
  --github-url <url>             GitHub API URL (default: "https://api.github.com")
  --token <token>                GitHub personal access token (or use GITHUB_TOKEN env var)
  --target-type <type>           target type: organization or enterprise (default: "organization")
  -f, --frameworks <frameworks>  compliance frameworks: owasp-top-10, mitre-top-10-kev, sans-top-25 (default: "owasp-top-10")
  -o, --output <format>          output format: json, markdown, html (default: "json")
  --days <days>                  number of days to look back (default: all time)
  --start-date <date>            start date for report (ISO format: YYYY-MM-DD)
  --end-date <date>              end date for report (ISO format: YYYY-MM-DD)
  --output-file <file>           output file path (default: stdout)
  --action                       running as GitHub Action (default: false)
  -v, --verbose                  verbose logging (default: false)
  -h, --help                     display help for command
```

### Environment Variables

```bash
# Required: GitHub Personal Access Token
export GITHUB_TOKEN="ghp_your_token_here"

# Optional: For GitHub Actions integration
export GITHUB_STEP_SUMMARY="/path/to/summary"
```

### 🔧 Current Features

- Fetch CodeQL alerts from GitHub organizations
- Automatic pagination handling for large result sets
- CWE extraction from alert rule tags
- Support for filtering alerts by various criteria
- Rate limit monitoring and connection testing
- Comprehensive error handling and logging

## 📁 Project Structure

```bash
src/
├── clients/          # API clients (GitHub, etc.)
├── types/           # TypeScript type definitions
├── utils/           # Utility functions (CWE processing, logging)
└── index.ts         # Main entry point

tests/               # Unit tests
.github/
└── instructions/    # Development instructions and mappings
```

## 🚀 Installation

```bash
npm install
```

## 🔧 Development

```bash
# Build the project
npm run build

# Run in development mode
npm run dev

# Run tests
npm test

# Run linting
npm run lint
```

## 📋 Next Steps (Upcoming Phases)

- **Phase 2**: Compliance framework mapping (OWASP, SANS, MITRE)
- **Phase 3**: Report generation (JSON, CSV, HTML formats)
- **Phase 4**: CLI interface and GitHub Action integration
- **Phase 5**: Testing and documentation

## 🔑 Environment Variables

```bash
GITHUB_TOKEN=your_github_personal_access_token
```

## 📚 Documentation

See `.github/instructions/` for detailed development instructions and compliance framework mappings.
