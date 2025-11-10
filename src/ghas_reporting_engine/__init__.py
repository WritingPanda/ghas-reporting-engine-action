"""
GHAS Reporting Engine - A CLI tool to generate compliance reports from GitHub Advanced Security findings.

This package provides functionality to:
- Fetch GHAS alerts from GitHub organizations and enterprises
- Map alerts to compliance frameworks (OWASP Top 10, SANS Top 25, MITRE KEV)
- Generate reports in multiple formats (JSON, CSV, HTML, PDF)
- Run as a CLI tool or GitHub Action
"""

__version__ = "0.1.0"
__author__ = "WritingPanda"

__all__ = ["__version__"]
