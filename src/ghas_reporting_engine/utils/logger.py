"""
Logging configuration for GHAS Reporting Engine.

This module provides centralized logging configuration for the application.
"""

import logging
import sys
from typing import Optional


def setup_logging(level: str = "INFO", format_string: Optional[str] = None) -> None:
    """Set up logging configuration."""

    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Default format
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format=format_string,
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # Set specific loggers to appropriate levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    # Create main logger
    logger = logging.getLogger("ghas_reporting_engine")
    logger.setLevel(numeric_level)

    logger.debug(f"Logging configured at {level} level")


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(f"ghas_reporting_engine.{name}")
