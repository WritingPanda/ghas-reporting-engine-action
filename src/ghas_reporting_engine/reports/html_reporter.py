"""
HTML report generator for GHAS reports.

This module generates rich, interactive HTML reports from GHAS alert analysis.
"""

from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .base_reporter import BaseReporter
from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger


logger = get_logger("html_reporter")


class HTMLReporter(BaseReporter):
    """HTML report generator."""
    
    def __init__(self, config):
        """Initialize the HTML reporter."""
        super().__init__(config)
        
        # Set up Jinja2 environment
        template_dir = Path(__file__).parent.parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader([template_dir / "html"]),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        
        # Add custom filters
        self.jinja_env.filters['format_datetime'] = self._format_datetime
        self.jinja_env.filters['format_percentage'] = self._format_percentage
        self.jinja_env.filters['safe_tojson'] = self._safe_tojson
        
        # Load CSS content
        self.css_content = self._load_css()
    
    def _get_format_name(self) -> str:
        """Get the format name for this reporter."""
        return "html"
    
    def _load_css(self) -> str:
        """Load CSS content from file."""
        css_path = Path(__file__).parent.parent / "templates" / "css" / "report.css"
        try:
            with open(css_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"CSS file not found: {css_path}")
            return ""
    
    def _format_datetime(self, dt_string: str) -> str:
        """Format datetime string for display."""
        try:
            if dt_string.endswith("Z"):
                dt_string = dt_string[:-1] + "+00:00"
            dt = datetime.fromisoformat(dt_string)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, AttributeError):
            return str(dt_string)
    
    def _format_percentage(self, value: float) -> str:
        """Format percentage value."""
        return f"{value:.1f}%"
    
    def _safe_tojson(self, obj) -> str:
        """Safely serialize object to JSON for use in templates."""
        from ..utils.json_utils import safe_json_dumps
        return safe_json_dumps(obj)
    
    def _generate_single_report(
        self, 
        analysis_result: AnalysisResult, 
        report_type: str, 
        output_path: Path
    ) -> None:
        """Generate a single HTML report for the specified type."""
        
        # Get common metadata
        metadata = self._get_common_metadata(analysis_result)
        
        # Prepare template context
        context = {
            "css_content": self.css_content,
            "title": self._get_report_title(report_type),
            "framework_type": report_type,
            **metadata,
        }
        
        # Add framework-specific data
        if report_type == "owasp":
            context.update(self._prepare_owasp_context(analysis_result))
        elif report_type == "sans":
            context.update(self._prepare_sans_context(analysis_result))
        elif report_type == "mitre":
            context.update(self._prepare_mitre_context(analysis_result))
        
        # Add common analysis data
        context.update(self._prepare_common_context(analysis_result))
        
        # Add chart data
        context.update(self._prepare_chart_data(analysis_result, report_type))
        
        # Sanitize context data before rendering, but preserve CSS content
        from ..utils.json_utils import sanitize_for_json
        
        # Extract CSS content before sanitization
        css_content = context.pop("css_content", "")
        
        # Sanitize the rest of the context
        sanitized_context = sanitize_for_json(context)
        
        # Add CSS content back (unsanitized)
        sanitized_context["css_content"] = css_content
        
        # Render template
        template = self.jinja_env.get_template("base.html")
        html_content = template.render(**sanitized_context)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write HTML file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def _get_report_title(self, report_type: str) -> str:
        """Get the report title based on type."""
        titles = {
            "owasp": "OWASP Top 10 2021 Compliance Report",
            "sans": "SANS Top 25 Software Errors Report",
            "mitre": "MITRE KEV Analysis Report",
        }
        return titles.get(report_type, f"{report_type.upper()} Security Report")
    
    def _prepare_owasp_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Prepare OWASP-specific template context."""
        owasp_data = analysis_result.framework_mappings.get("owasp", {})
        
        return {
            "framework_data": {
                "name": "OWASP Top 10 2021",
                "type": "owasp",
                "total_mapped_alerts": owasp_data.get("total_mapped_alerts", 0),
                "categories": owasp_data.get("category_counts", {}),
                "coverage": {
                    "categories_found": len(owasp_data.get("category_counts", {})),
                    "total_categories": 10,
                    "coverage_percentage": (len(owasp_data.get("category_counts", {})) / 10) * 100,
                },
            },
        }
    
    def _prepare_sans_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Prepare SANS-specific template context."""
        sans_data = analysis_result.framework_mappings.get("sans", {})
        
        return {
            "framework_data": {
                "name": "SANS Top 25 Most Dangerous Software Errors",
                "type": "sans",
                "total_mapped_alerts": sans_data.get("total_mapped_alerts", 0),
                "rankings": sans_data.get("cwe_counts", {}),
                "coverage": {
                    "cwes_found": len(sans_data.get("cwe_counts", {})),
                    "total_cwes": 25,
                    "coverage_percentage": (len(sans_data.get("cwe_counts", {})) / 25) * 100,
                },
            },
        }
    
    def _prepare_mitre_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Prepare MITRE KEV-specific template context."""
        mitre_data = analysis_result.framework_mappings.get("mitre", {})
        
        return {
            "framework_data": {
                "name": "MITRE Top 10 Known Exploited Vulnerabilities",
                "type": "mitre_kev",
                "total_mapped_alerts": mitre_data.get("total_mapped_alerts", 0),
                "kev_rankings": mitre_data.get("cwe_counts", {}),
                "coverage": {
                    "cwes_found": len(mitre_data.get("cwe_counts", {})),
                    "total_cwes": 10,
                    "coverage_percentage": (len(mitre_data.get("cwe_counts", {})) / 10) * 100,
                },
            },
        }
    
    def _prepare_common_context(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Prepare common template context."""
        # Format CWE analysis for template
        cwe_analysis = analysis_result.cwe_analysis
        cwe_details = cwe_analysis.get("cwe_details", {})
        
        # Limit to top 20 CWEs for HTML display
        top_cwe_details = dict(
            sorted(
                cwe_details.items(),
                key=lambda x: x[1]["total_alerts"],
                reverse=True
            )[:20]
        )
        
        # Format repository analysis
        repo_analysis = analysis_result.repository_analysis
        top_repos = [
            {"name": name, "count": count}
            for name, count in repo_analysis.get("top_repositories_by_alerts", {}).items()
        ][:10]
        
        return {
            "cwe_analysis": {
                "total_unique_cwes": cwe_analysis.get("total_unique_cwes", 0),
                "cwe_details": top_cwe_details,
            },
            "repository_analysis": {
                "total_repositories": repo_analysis.get("total_repositories", 0),
                "top_repositories_by_alerts": top_repos,
            },
            "recommendations": analysis_result.recommendations,
        }
    
    def _prepare_chart_data(self, analysis_result: AnalysisResult, report_type: str) -> Dict[str, Any]:
        """Prepare data for charts."""
        severity_analysis = analysis_result.severity_analysis
        
        # Severity distribution chart data
        severity_counts = severity_analysis.get("severity_counts", {})
        severity_colors = {
            "critical": "#e74c3c",
            "high": "#f39c12", 
            "medium": "#f1c40f",
            "low": "#27ae60",
        }
        
        severity_data = {
            "labels": list(severity_counts.keys()),
            "values": list(severity_counts.values()),
            "colors": [severity_colors.get(sev, "#95a5a6") for sev in severity_counts.keys()],
        }
        
        # Framework distribution chart data
        framework_data = analysis_result.framework_mappings.get(report_type, {})
        
        if report_type == "owasp":
            categories = framework_data.get("category_counts", {})
            framework_chart_data = {
                "labels": [self._shorten_owasp_category(cat) for cat in categories.keys()],
                "values": list(categories.values()),
            }
        elif report_type == "sans":
            rankings = framework_data.get("cwe_counts", {})
            # Sort by alert count and take top 10
            sorted_rankings = sorted(rankings.items(), key=lambda x: x[1], reverse=True)[:10]
            framework_chart_data = {
                "labels": [cwe for cwe, _ in sorted_rankings],
                "values": [count for _, count in sorted_rankings],
            }
        elif report_type == "mitre":
            kev_rankings = framework_data.get("cwe_counts", {})
            framework_chart_data = {
                "labels": list(kev_rankings.keys()),
                "values": list(kev_rankings.values()),
            }
        else:
            framework_chart_data = {"labels": [], "values": []}
        
        return {
            "severity_data": severity_data,
            "framework_chart_data": framework_chart_data,
        }
    
    def _shorten_owasp_category(self, category: str) -> str:
        """Shorten OWASP category names for chart display."""
        # Extract just the category name part after the dash
        if " - " in category:
            return category.split(" - ", 1)[1][:30]  # Limit to 30 chars
        return category[:30]