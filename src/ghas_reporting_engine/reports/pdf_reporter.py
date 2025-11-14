"""PDF reporting placeholder.

PDF generation is temporarily disabled while the feature is under review.
"""

from pathlib import Path

from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger

logger = get_logger("pdf_reporter")


class PDFReporter:  # pragma: no cover - disabled feature
    """Placeholder reporter while PDF support is disabled."""

    def __init__(self, *args, **kwargs) -> None:
        logger.warning("PDFReporter initialized but PDF support is currently disabled.")
        raise RuntimeError("PDF reporting is temporarily disabled")

    def generate(self, analysis_result: AnalysisResult, output_path: Path) -> Path:
        raise RuntimeError("PDF reporting is temporarily disabled")
