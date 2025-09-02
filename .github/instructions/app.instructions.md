# GHAS Reporting Engine

This document provides instructions for building the GHAS reporting engine.

## Core Concepts for LLM Understanding

- This app will be written in Typescript and transpiled to Javascript.
- This app will run within a GitHub Action.
- This app will provide the user with a report on their GitHub Advanced Security findings and how they map to compliance frameworks, like the OWASP Top 10, SANS Top 25, and the MITRE Top 25 Known Exploited Vulnerabilities.
- The user will be able to choose which reports they want to generate and for what time period.
- The app will fetch data from the GitHub API and process it to generate the requested reports.
- The app will be designed with modularity in mind, allowing for easy updates and maintenance.
- The app will include comprehensive error handling and logging to facilitate troubleshooting and ensure reliability.
- The app will have tests to validate its functionality and ensure that it meets the specified requirements.
- The app will provide users with the ability to choose a single repo, a set of repos, an organization, or an enterprise to retrieve alerts from and create a report.
- The report will be delivered in the summary of the action and exported as a markdown file to be downloaded by the user.

### Links for Compliance Frameworks

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [MITRE Top 10 Known Exploited Vulnerabilities](https://cwe.mitre.org/top25/archive/2024/2024_kev_list.html)
