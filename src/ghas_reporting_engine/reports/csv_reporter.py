"""
CSV report generator.

Generates CSV reports of GHAS analysis results.
"""

import csv
from pathlib import Path
from typing import Any, Dict, List

from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger
from .base_reporter import BaseReporter

logger = get_logger("csv_reporter")


class CSVReporter(BaseReporter):
    """Generate CSV format reports."""

    def generate(self, analysis_result: AnalysisResult, output_path: Path) -> Path:
        """Generate CSV report."""
        logger.info(f"Generating CSV report: {output_path}")

        try:
            with open(output_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)

                # Write summary section
                self._write_summary_section(writer, analysis_result)

                # Write blank line
                writer.writerow([])

                # Write CWE analysis section
                self._write_cwe_section(writer, analysis_result)

                # Write blank line
                writer.writerow([])

                # Write repository analysis section
                self._write_repository_section(writer, analysis_result)

                # Write blank line
                writer.writerow([])

                # Write framework mappings section
                self._write_framework_section(writer, analysis_result)

            logger.info(f"CSV report generated successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            raise

    def _write_summary_section(self, writer, analysis_result: AnalysisResult) -> None:
        """Write summary section to CSV."""
        writer.writerow(["SUMMARY"])
        writer.writerow(["Metric", "Count"])

        summary = analysis_result.summary
        writer.writerow(["Total Alerts", summary.get("total_alerts", 0)])
        writer.writerow(["Open Alerts", summary.get("open_alerts", 0)])
        writer.writerow(["Dismissed Alerts", summary.get("dismissed_alerts", 0)])
        writer.writerow(["Fixed Alerts", summary.get("fixed_alerts", 0)])

        # Add severity breakdown
        severity = analysis_result.severity_analysis
        if severity:
            writer.writerow([])
            writer.writerow(["Severity Distribution"])
            for level, count in severity.get("severity_counts", {}).items():
                writer.writerow([level.capitalize(), count])

    def _write_cwe_section(self, writer, analysis_result: AnalysisResult) -> None:
        """Write CWE analysis section to CSV."""
        writer.writerow(["CWE ANALYSIS"])
        writer.writerow(["CWE", "Alert Count", "Severity Distribution", "State Distribution"])

        cwe_data = analysis_result.cwe_analysis.get("cwe_details", {})

        # Sort by alert count descending
        sorted_cwes = sorted(cwe_data.items(), key=lambda x: x[1].get("total_alerts", 0), reverse=True)

        for cwe, details in sorted_cwes:
            severity_dist = "; ".join(
                [f"{k}:{v}" for k, v in details.get("severity_distribution", {}).items()]
            )
            state_dist = "; ".join([f"{k}:{v}" for k, v in details.get("state_distribution", {}).items()])

            writer.writerow([cwe, details.get("total_alerts", 0), severity_dist, state_dist])

    def _write_repository_section(
        self, writer, analysis_result: AnalysisResult
    ) -> None:
        """Write repository analysis section to CSV."""
        writer.writerow(["REPOSITORY ANALYSIS"])
        writer.writerow(["Repository", "Total Alerts", "Unique CWEs", "Unique Rules"])

        repo_data = analysis_result.repository_analysis.get("repository_details", {})

        # Sort by alert count descending
        sorted_repos = sorted(
            repo_data.items(), key=lambda x: x[1].get("total_alerts", 0), reverse=True
        )

        for repo, details in sorted_repos:
            writer.writerow(
                [
                    repo,
                    details.get("total_alerts", 0),
                    details.get("unique_cwes", 0),
                    details.get("unique_rules", 0),
                ]
            )

    def _write_framework_section(
        self, writer, analysis_result: AnalysisResult
    ) -> None:
        """Write framework mappings section to CSV."""
        writer.writerow(["FRAMEWORK MAPPINGS"])

        frameworks = analysis_result.framework_mappings

        # OWASP
        if "owasp" in frameworks:
            writer.writerow([])
            writer.writerow(["OWASP Top 10 2021"])
            writer.writerow(["Category", "Alert Count"])

            owasp_data = frameworks["owasp"]
            category_counts = owasp_data.get("category_alerts", {})

            for category, count in category_counts.items():
                writer.writerow([category, count])

        # SANS
        if "sans" in frameworks:
            writer.writerow([])
            writer.writerow(["SANS Top 25"])
            writer.writerow(["CWE", "Alert Count", "Rank"])

            sans_data = frameworks["sans"]
            mappings = sans_data.get("mappings", {})
            cwe_counts = sans_data.get("cwe_counts", {})

            for cwe, count in cwe_counts.items():
                rank = mappings.get(cwe, {}).get("rank", "N/A")
                writer.writerow([cwe, count, rank])

        # MITRE KEV
        if "mitre" in frameworks:
            writer.writerow([])
            writer.writerow(["MITRE Top 10 KEV"])
            writer.writerow(["CWE", "Alert Count", "Rank", "Vulnerability Count"])

            mitre_data = frameworks["mitre"]
            mappings = mitre_data.get("mappings", {})
            cwe_counts = mitre_data.get("cwe_counts", {})

            for cwe, count in cwe_counts.items():
                rank = mappings.get(cwe, {}).get("rank", "N/A")
                vuln_count = mappings.get(cwe, {}).get("vulnerability_count", "N/A")
                writer.writerow([cwe, count, rank, vuln_count])
