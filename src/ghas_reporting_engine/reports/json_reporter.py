"""
JSON report generator.

Generates comprehensive JSON reports of GHAS analysis results.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from ..processors.data_analyzer import AnalysisResult
from ..utils.json_utils import safe_json_dumps, sanitize_for_json
from ..utils.logger import get_logger
from .base_reporter import BaseReporter

logger = get_logger("json_reporter")


class JSONReporter(BaseReporter):
    """Generate JSON format reports."""

    def generate(self, analysis_result: AnalysisResult, framework: str, output_path: Path) -> Path:
        """Generate JSON report."""
        logger.info(f"Generating JSON report: {output_path}")

        # Build complete report structure
        report_data = self._build_report(analysis_result, framework)

        # Sanitize for JSON serialization
        sanitized_data = sanitize_for_json(report_data)

        # Write to file
        try:
            with open(output_path, "w") as f:
                f.write(safe_json_dumps(sanitized_data, indent=2))

            logger.info(f"JSON report generated successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def _build_report(self, analysis_result: AnalysisResult, framework: str) -> Dict[str, Any]:
        """Build the complete report structure."""
        metadata = self._get_common_metadata(analysis_result, framework)
        framework_mapping = analysis_result.framework_mappings.get(framework, {})

        report = {
            "metadata": metadata,
            "framework": framework,
            "framework_mapping": framework_mapping,
            "summary": analysis_result.summary,
            "severity_analysis": analysis_result.severity_analysis,
            "cwe_analysis": analysis_result.cwe_analysis,
            "repository_analysis": analysis_result.repository_analysis,
            "active_alerts_by_repository": analysis_result.active_alerts_by_repository,
            "trend_analysis": analysis_result.trend_analysis,
            "unmapped_cwes": analysis_result.unmapped_cwes,
            "recommendations": analysis_result.recommendations,
        }

        return report
