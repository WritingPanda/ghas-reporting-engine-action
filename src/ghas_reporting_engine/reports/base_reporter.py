"""
Base reporter class for GHAS reports.

This module provides the base class and common functionality
for all report generators.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..config import Config
from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger


logger = get_logger("base_reporter")


class BaseReporter(ABC):
    """Base class for all report generators."""
    
    def __init__(self, config: Config):
        """Initialize the base reporter."""
        self.config = config
        self.report_format = self._get_format_name()
    
    @abstractmethod
    def _get_format_name(self) -> str:
        """Get the format name for this reporter."""
        pass
    
    @abstractmethod
    def _generate_single_report(
        self, 
        analysis_result: AnalysisResult, 
        report_type: str, 
        output_path: Path
    ) -> None:
        """Generate a single report for the specified type."""
        pass
    
    def generate_reports(self, analysis_result: AnalysisResult) -> List[Path]:
        """Generate all requested reports."""
        generated_paths = []
        
        for report_type in self.config.report_types:
            if report_type in analysis_result.framework_mappings:
                output_path = self.config.get_report_path(report_type, self.report_format)
                
                logger.info(f"Generating {report_type} report in {self.report_format} format: {output_path}")
                
                try:
                    self._generate_single_report(analysis_result, report_type, output_path)
                    generated_paths.append(output_path)
                    logger.info(f"Successfully generated report: {output_path}")
                except Exception as e:
                    logger.error(f"Failed to generate {report_type} report: {e}")
                    continue
        
        return generated_paths
    
    def _get_common_metadata(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Get common metadata for all reports."""
        from datetime import timezone
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "GHAS Reporting Engine",
            "version": "0.1.0",
            "target_name": self.config.target_name,
            "target_type": self.config.target_type,
            "report_period": {
                "since": self.config.since_date.isoformat(),
                "until": self.config.until_date.isoformat(),
                "days_back": self.config.days_back,
            },
            "filters": {
                "include_dismissed": self.config.include_dismissed,
                "severity_filters": self.config.severity_filters or [],
            },
            "summary": {
                "total_alerts": analysis_result.summary.total_alerts,
                "open_alerts": analysis_result.summary.open_alerts,
                "dismissed_alerts": analysis_result.summary.dismissed_alerts,
                "fixed_alerts": analysis_result.summary.fixed_alerts,
            },
        }
    
    def _format_severity_distribution(self, severity_dist: Dict[str, int]) -> Dict[str, Any]:
        """Format severity distribution with percentages."""
        total = sum(severity_dist.values()) if severity_dist else 0
        
        formatted = {}
        for severity, count in severity_dist.items():
            percentage = (count / total) * 100 if total > 0 else 0
            formatted[severity] = {
                "count": count,
                "percentage": round(percentage, 1),
            }
        
        return formatted
    
    def _get_top_items(self, items_dict: Dict[str, int], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top items from a dictionary, sorted by count."""
        sorted_items = sorted(items_dict.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"name": name, "count": count}
            for name, count in sorted_items[:limit]
        ]