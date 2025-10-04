"""
JSON report generator for GHAS reports.

This module generates comprehensive JSON reports from GHAS alert analysis.
"""

import json
from pathlib import Path
from typing import Dict, Any

from .base_reporter import BaseReporter
from ..processors.data_analyzer import AnalysisResult
from ..frameworks.owasp_top10 import OWASPTop10Processor
from ..frameworks.sans_top25 import SANSTop25Processor
from ..frameworks.mitre_kev import MITREKEVProcessor
from ..utils.logger import get_logger


logger = get_logger("json_reporter")


class JSONReporter(BaseReporter):
    """JSON report generator."""
    
    def __init__(self, config):
        """Initialize the JSON reporter."""
        super().__init__(config)
        self.owasp_processor = OWASPTop10Processor()
        self.sans_processor = SANSTop25Processor()
        self.mitre_processor = MITREKEVProcessor()
    
    def _get_format_name(self) -> str:
        """Get the format name for this reporter."""
        return "json"
    
    def _generate_single_report(
        self, 
        analysis_result: AnalysisResult, 
        report_type: str, 
        output_path: Path
    ) -> None:
        """Generate a single JSON report for the specified type."""
        
        # Get common metadata
        report_data = self._get_common_metadata(analysis_result)
        
        # Add framework-specific data
        if report_type == "owasp":
            report_data.update(self._generate_owasp_data(analysis_result))
        elif report_type == "sans":
            report_data.update(self._generate_sans_data(analysis_result))
        elif report_type == "mitre":
            report_data.update(self._generate_mitre_data(analysis_result))
        
        # Add common analysis data
        report_data.update({
            "cwe_analysis": self._format_cwe_analysis(analysis_result.cwe_analysis),
            "repository_analysis": self._format_repository_analysis(analysis_result.repository_analysis),
            "severity_analysis": self._format_severity_analysis(analysis_result.severity_analysis),
            "trend_analysis": analysis_result.trend_analysis,
            "unmapped_cwes": analysis_result.unmapped_cwes,
            "recommendations": analysis_result.recommendations,
        })
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write JSON file
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _generate_owasp_data(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Generate OWASP-specific report data."""
        owasp_data = analysis_result.framework_mappings.get("owasp", {})
        
        return {
            "framework": {
                "name": "OWASP Top 10 2021",
                "type": "owasp",
                "url": "https://owasp.org/www-project-top-ten/",
            },
            "categories": owasp_data.get("category_counts", {}),
            "mappings": owasp_data.get("mappings", {}),
            "total_mapped_alerts": owasp_data.get("total_mapped_alerts", 0),
            "coverage": {
                "categories_found": len(owasp_data.get("category_counts", {})),
                "total_categories": 10,
                "coverage_percentage": (len(owasp_data.get("category_counts", {})) / 10) * 100,
            },
        }
    
    def _generate_sans_data(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Generate SANS-specific report data."""
        sans_data = analysis_result.framework_mappings.get("sans", {})
        
        return {
            "framework": {
                "name": "SANS Top 25 Most Dangerous Software Errors",
                "type": "sans",
                "url": "https://www.sans.org/top25-software-errors/",
            },
            "rankings": sans_data.get("cwe_counts", {}),
            "mappings": sans_data.get("mappings", {}),
            "total_mapped_alerts": sans_data.get("total_mapped_alerts", 0),
            "top_5_cwes": sans_data.get("top_5_cwes", {}),
            "coverage": {
                "cwes_found": len(sans_data.get("cwe_counts", {})),
                "total_cwes": 25,
                "coverage_percentage": (len(sans_data.get("cwe_counts", {})) / 25) * 100,
            },
        }
    
    def _generate_mitre_data(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Generate MITRE KEV-specific report data."""
        mitre_data = analysis_result.framework_mappings.get("mitre", {})
        
        return {
            "framework": {
                "name": "MITRE Top 10 Known Exploited Vulnerabilities",
                "type": "mitre_kev",
                "url": "https://cwe.mitre.org/top25/archive/2024/2024_kev_list.html",
            },
            "kev_rankings": mitre_data.get("cwe_counts", {}),
            "mappings": mitre_data.get("mappings", {}),
            "total_mapped_alerts": mitre_data.get("total_mapped_alerts", 0),
            "critical_vulnerabilities": mitre_data.get("critical_vulnerabilities", {}),
            "coverage": {
                "cwes_found": len(mitre_data.get("cwe_counts", {})),
                "total_cwes": 10,
                "coverage_percentage": (len(mitre_data.get("cwe_counts", {})) / 10) * 100,
            },
        }
    
    def _format_cwe_analysis(self, cwe_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Format CWE analysis data for JSON output."""
        if not cwe_analysis:
            return {}
        
        formatted = {
            "total_unique_cwes": cwe_analysis.get("total_unique_cwes", 0),
            "top_cwes": cwe_analysis.get("top_cwes", {}),
        }
        
        # Format CWE details (limit to top 20 for JSON size)
        cwe_details = cwe_analysis.get("cwe_details", {})
        top_cwes = sorted(
            cwe_details.items(),
            key=lambda x: x[1]["total_alerts"],
            reverse=True
        )[:20]
        
        formatted["cwe_details"] = {
            cwe: {
                "total_alerts": details["total_alerts"],
                "severity_distribution": self._format_severity_distribution(
                    details["severity_distribution"]
                ),
                "state_distribution": details["state_distribution"],
                "top_repositories": dict(list(details["top_repositories"].items())[:5]),
                "first_seen": details["first_seen"],
                "last_seen": details["last_seen"],
            }
            for cwe, details in top_cwes
        }
        
        return formatted
    
    def _format_repository_analysis(self, repo_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Format repository analysis data for JSON output."""
        if not repo_analysis:
            return {}
        
        return {
            "total_repositories": repo_analysis.get("total_repositories", 0),
            "top_repositories_by_alerts": self._get_top_items(
                repo_analysis.get("top_repositories_by_alerts", {}), 
                limit=10
            ),
            "repository_summary": {
                repo: {
                    "total_alerts": details["total_alerts"],
                    "severity_distribution": self._format_severity_distribution(
                        details["severity_distribution"]
                    ),
                    "state_distribution": details["state_distribution"],
                    "unique_cwes": details["unique_cwes"],
                    "unique_rules": details["unique_rules"],
                }
                for repo, details in list(repo_analysis.get("repository_details", {}).items())[:10]
            },
        }
    
    def _format_severity_analysis(self, severity_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Format severity analysis data for JSON output."""
        if not severity_analysis:
            return {}
        
        return {
            "severity_counts": severity_analysis.get("severity_counts", {}),
            "severity_percentages": {
                severity: round(percentage, 1)
                for severity, percentage in severity_analysis.get("severity_percentages", {}).items()
            },
            "critical_and_high": severity_analysis.get("critical_and_high", 0),
            "medium_and_low": severity_analysis.get("medium_and_low", 0),
            "severity_distribution": self._format_severity_distribution(
                severity_analysis.get("severity_counts", {})
            ),
        }