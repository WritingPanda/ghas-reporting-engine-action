"""
HTML report generator.

Generates professional HTML reports of GHAS analysis results.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..processors.data_analyzer import AnalysisResult
from ..utils.json_utils import sanitize_for_json
from ..utils.logger import get_logger
from .base_reporter import BaseReporter

logger = get_logger("html_reporter")


class HTMLReporter(BaseReporter):
    """Generate HTML format reports."""

    def __init__(self, config):
        """Initialize HTML reporter with template environment."""
        super().__init__(config)

        # Set up Jinja2 template environment
        template_dir = Path(__file__).parent.parent / "templates" / "html"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html", "xml"])
        )

    def generate(self, analysis_result: AnalysisResult, framework: str, output_path: Path) -> Path:
        """Generate HTML report."""
        logger.info(f"Generating HTML report: {output_path}")

        try:
            # Load template
            template = self.env.get_template("base.html")

            # Prepare context
            context = self._build_context(analysis_result, framework)

            # Render template
            html_content = template.render(**context)

            # Write to file
            with open(output_path, "w") as f:
                f.write(html_content)

            logger.info(f"HTML report generated successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def _build_context(self, analysis_result: AnalysisResult, framework: str) -> dict:
        """Build template context."""
        # Get common metadata
        metadata = self._get_common_metadata(analysis_result, framework)
        framework_data = analysis_result.framework_mappings.get(framework, {})

        # Sanitize all data for templates
        context = sanitize_for_json(
            {
                "metadata": metadata,
                "framework": framework,
                "framework_data": framework_data,
                "summary": analysis_result.summary,
                "severity_analysis": analysis_result.severity_analysis,
                "cwe_analysis": analysis_result.cwe_analysis,
                "repository_analysis": analysis_result.repository_analysis,
                "active_alerts_by_repository": analysis_result.active_alerts_by_repository,
                "trend_analysis": analysis_result.trend_analysis,
                "unmapped_cwes": analysis_result.unmapped_cwes,
                "recommendations": analysis_result.recommendations,
            }
        )

        # Add CSS content directly (read from file)
        css_path = Path(__file__).parent.parent / "templates" / "css" / "report.css"
        inline_css = ""
        inline_css_tag = ""
        if css_path.exists():
            inline_css = css_path.read_text(encoding="utf-8")
            inline_css_tag = f"<style>\n{inline_css}\n</style>"

        context["inline_css"] = inline_css
        context["inline_css_tag"] = inline_css_tag

        return context
