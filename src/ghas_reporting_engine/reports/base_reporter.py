"""
Base reporter class.

Provides common functionality for all report generators.
"""

from abc import ABC, abstractmethod
import datetime as dtime
from pathlib import Path
from typing import Any, Dict, List

from ..config import Config
from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger

logger = get_logger("base_reporter")


class BaseReporter(ABC):
    """Abstract base class for all reporters."""

    def __init__(self, config: Config):
        """Initialize the reporter with configuration."""
        self.config = config

    @abstractmethod
    def generate(self, analysis_result: AnalysisResult, framework: str, output_path: Path) -> Path:
        """Generate the report for a single framework and return the generated file path."""
        pass

    def generate_reports(self, analysis_result: AnalysisResult) -> List[Path]:
        """
        Generate reports for all requested frameworks.
        
        Returns a list of paths to generated report files.
        """
        generated_reports = []
        
        # Generate one report per framework
        for framework in self.config.report_types:
            report_path = self.config.get_report_path(framework, self._get_format_extension())
            
            try:
                output_path = self.generate(analysis_result, framework, report_path)
                generated_reports.append(output_path)
                logger.info(f"Generated {framework} report: {output_path}")
            except Exception as e:
                logger.error(f"Failed to generate {framework} report: {e}")
                raise
        
        return generated_reports

    def _get_format_extension(self) -> str:
        """Get the file extension for this reporter's format."""
        # Default implementation - subclasses can override if needed
        class_name = self.__class__.__name__.lower()
        if "json" in class_name:
            return "json"
        elif "csv" in class_name:
            return "csv"
        elif "html" in class_name:
            return "html"
        elif "pdf" in class_name:
            return "pdf"
        else:
            return "txt"

    def _get_common_metadata(self, analysis_result: AnalysisResult, framework: str) -> Dict[str, Any]:
        """Get common metadata for all reports."""
        return {
            "generated_at": dtime.datetime.now(tz=dtime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "report_version": "1.0",
            "target": self.config.target_name,
            "target_type": self.config.target_type,
            "date_range": {
            "since": self.config.since_date.strftime("%Y-%m-%d") if self.config.since_date else None,
            "until": self.config.until_date.strftime("%Y-%m-%d") if self.config.until_date else None,
            "days": self.config.days_back,
            },
            "framework": framework,
            "frameworks_requested": self.config.report_types,
            "total_alerts": analysis_result.summary.get("total_alerts", 0),
            "alert_summary": {
            "open": analysis_result.summary.get("open_alerts", 0),
            "dismissed": analysis_result.summary.get("dismissed_alerts", 0),
            "fixed": analysis_result.summary.get("fixed_alerts", 0),
            },
        }
