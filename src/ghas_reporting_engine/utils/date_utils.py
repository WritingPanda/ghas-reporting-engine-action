"""
Date and time utilities for GHAS Reporting Engine.

This module provides utility functions for working with dates and times.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from dateutil import parser as date_parser


def parse_iso_date(date_string: str) -> datetime:
    """Parse an ISO 8601 date string."""
    return date_parser.isoparse(date_string)


def format_date_for_display(dt: datetime) -> str:
    """Format a datetime for display purposes."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_date_for_filename(dt: datetime) -> str:
    """Format a datetime for use in filenames."""
    return dt.strftime("%Y%m%d_%H%M%S")


def get_date_range_string(since: datetime, until: datetime) -> str:
    """Get a human-readable date range string."""
    since_str = since.strftime("%Y-%m-%d")
    until_str = until.strftime("%Y-%m-%d")
    return f"{since_str} to {until_str}"


def days_ago(days: int) -> datetime:
    """Get a datetime that is the specified number of days ago."""
    return datetime.utcnow() - timedelta(days=days)


def normalize_datetime(dt: datetime) -> datetime:
    """Normalize a datetime to UTC."""
    if dt.tzinfo is None:
        # Assume UTC if no timezone info
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_within_range(dt: datetime, since: datetime, until: datetime) -> bool:
    """Check if a datetime is within the specified range."""
    dt_normalized = normalize_datetime(dt)
    since_normalized = normalize_datetime(since)
    until_normalized = normalize_datetime(until)
    
    return since_normalized <= dt_normalized <= until_normalized