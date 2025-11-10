"""
PDF report generator.

Generates professional PDF reports using WeasyPrint.
"""

from pathlib import Path

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    WEASYPRINT_AVAILABLE = False
    WEASYPRINT_ERROR = str(e)

from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger
from .html_reporter import HTMLReporter

logger = get_logger("pdf_reporter")


class PDFReporter(HTMLReporter):
    """Generate PDF format reports using WeasyPrint."""

    def generate(self, analysis_result: AnalysisResult, output_path: Path) -> Path:
        """Generate PDF report."""
        if not WEASYPRINT_AVAILABLE:
            error_msg = (
                f"PDF generation is not available. WeasyPrint dependency error: {WEASYPRINT_ERROR}\n\n"
                "To enable PDF reports, install system dependencies:\n"
                "  macOS:        brew install pango cairo gdk-pixbuf libffi\n"
                "  Ubuntu/Debian: sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev\n"
                "  Fedora/RHEL:  sudo dnf install pango cairo gdk-pixbuf2 libffi-devel\n\n"
                "Alternatively, use other formats: --report-formats json,csv,html"
            )
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        logger.info(f"Generating PDF report: {output_path}")

        try:
            # Generate HTML content first
            template = self.env.get_template("base.html")
            context = self._build_context(analysis_result)
            html_content = template.render(**context)

            # Convert HTML to PDF using WeasyPrint
            HTML(string=html_content).write_pdf(output_path)

            logger.info(f"PDF report generated successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise
