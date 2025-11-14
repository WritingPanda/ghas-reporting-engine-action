# GHAS Reporting Engine

This document provides instructions for building the GHAS reporting engine.

## Core Concepts for LLM Understanding

This app will:

- be written in Python
- use the uv package manager
- be a command-line interface (CLI) application that can be run as a GitHub Action or locally
- interact with the GitHub API to fetch GitHub Advanced Security (GHAS) alert data
- process and analyze the fetched data to generate reports based on compliance frameworks
- provide the user with a report on their GitHub Advanced Security findings and how they map to compliance frameworks, like the OWASP Top 10, SANS Top 25, and the MITRE Top 25 Known Exploited Vulnerabilities
- allow the user to choose which reports they want to generate and for what time period
- be designed with modularity in mind, allowing for easy updates and maintenance
- include comprehensive error handling and logging to facilitate troubleshooting and ensure reliability
- have tests to validate its functionality and ensure that it does generate reports and maps the CWEs appropriately
- provide users with the ability to choose an organization or an enterprise to retrieve alerts from and create a report
- have a report delivered in the summary of the action

### Links for Compliance Frameworks

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [MITRE Top 10 Known Exploited Vulnerabilities](https://cwe.mitre.org/top25/archive/2024/2024_kev_list.html)

### Links for instruction files and resources for frameworks

Review the following files for additional context and data to help build this application:

- [CodeQL CWE Coverage CSV](../instructions/codeql_cwe_coverage.csv)
- [CodeQL CWE Coverage Instructions](../instructions/codeqlcwecoverage.instructions.md)
- [MITRE KEV Mapping and Instructions](../instructions/mitrekev.instructions.md)
- [OWASP Top 10 Mapping and Instructions](../instructions/owasptop10.instructions.md)
- [SANS Top 25 Mapping and Instructions](../instructions/sanstop25.instructions.md)
- [CodeQL Alert Sample Data](../instructions/sample-output.instructions.json)

## Application Design

The application must be a CLI app that can be run as a GitHub Action or locally. It should accept the following inputs:

- GitHub token (for API access)
- Organization or enterprise name
- Report type (e.g., OWASP Top 10, SANS Top 25, MITRE Top 10)
- Report format (e.g., JSON, CSV, HTML)
- Time period for the report (e.g., last 7 days, last 30 days) (optional)

For the HTML report format, the application should generate a well-structured HTML file that includes:

- A title
- A summary of the findings
- A date of the report generation
- The total number of findings
- The organization or enterprise name
- A detailed breakdown of the findings by category
- Links to the relevant compliance framework sections
- Visualizations (e.g., charts or graphs) to represent the data
- The reports should be built as a template that can be easily updated or modified in the future and have data injected into it as needed

The application should be modular, with separate functions or classes for:

- Fetching data from the GitHub API
- Processing and analyzing the data
- Generating reports in different formats
- Handling errors and logging

The GitHub Action workflow should be defined in a YAML file, specifying the steps to:

- Checkout the repository
- Set up the Python environment
- Install dependencies
- Run the application with the provided inputs
- Upload the generated report as an artifact and include it in the action summary
- Allow for downloading of the report artifact, which should be available for 7 days by default

The application should include tests to validate its functionality, including:

- Unit tests for individual functions or classes
- Integration tests to ensure the application works as expected when run as a GitHub Action or a CLI app
- Tests to verify that the reports are generated correctly and include the expected data

## Documentation

The application should include comprehensive documentation, including:

- A README file with an overview of the application, installation instructions, usage examples, and information on how to contribute
- Inline comments in the code to explain the functionality of different sections
- A CONTRIBUTING file with guidelines for contributing to the project
- A LICENSE file specifying the open-source license for the project
- A CODEOWNERS file to define code ownership and review requirements
- Examples of generated reports in different formats (JSON, CSV, HTML)
