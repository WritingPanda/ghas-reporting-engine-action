"""
Input validation utilities for GHAS Reporting Engine.

This module provides utility functions for validating user inputs.
"""

import re
from typing import List, Optional

from ..config import Config


def validate_github_token(token: str) -> bool:
    """Validate GitHub token format."""
    if not token:
        return False
    
    # GitHub tokens can be:
    # - Personal access tokens (classic): ghp_...
    # - Personal access tokens (fine-grained): github_pat_...
    # - App tokens: ghs_...
    # - Installation tokens: ghu_...
    # - Or older format tokens
    
    token_patterns = [
        r"^ghp_[a-zA-Z0-9]{36}$",  # Personal access token (classic)
        r"^github_pat_[a-zA-Z0-9_]{82}$",  # Personal access token (fine-grained)
        r"^ghs_[a-zA-Z0-9]{36}$",  # App token
        r"^ghu_[a-zA-Z0-9]{36}$",  # Installation token
        r"^[a-fA-F0-9]{40}$",  # Older 40-character tokens
    ]
    
    return any(re.match(pattern, token) for pattern in token_patterns)


def validate_organization_name(name: str) -> bool:
    """Validate GitHub organization name format."""
    if not name:
        return False
    
    # GitHub organization names can contain alphanumeric characters and hyphens
    # Cannot start or end with hyphens
    # Must be 1-39 characters long
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,37}[a-zA-Z0-9])?$"
    return bool(re.match(pattern, name))


def validate_report_types(report_types: List[str]) -> List[str]:
    """Validate and normalize report types."""
    valid_types = {"owasp", "sans", "mitre"}
    normalized_types = [rt.lower().strip() for rt in report_types]
    
    invalid_types = set(normalized_types) - valid_types
    if invalid_types:
        raise ValueError(f"Invalid report types: {', '.join(invalid_types)}")
    
    return normalized_types


def validate_report_formats(report_formats: List[str]) -> List[str]:
    """Validate and normalize report formats."""
    valid_formats = {"json", "csv", "html"}
    normalized_formats = [rf.lower().strip() for rf in report_formats]
    
    invalid_formats = set(normalized_formats) - valid_formats
    if invalid_formats:
        raise ValueError(f"Invalid report formats: {', '.join(invalid_formats)}")
    
    return normalized_formats


def validate_severity_filters(severity_filters: Optional[List[str]]) -> Optional[List[str]]:
    """Validate and normalize severity filters."""
    if not severity_filters:
        return None
    
    valid_severities = {"critical", "high", "medium", "low"}
    normalized_severities = [sf.lower().strip() for sf in severity_filters]
    
    invalid_severities = set(normalized_severities) - valid_severities
    if invalid_severities:
        raise ValueError(f"Invalid severity filters: {', '.join(invalid_severities)}")
    
    return normalized_severities


def validate_days_back(days: int) -> int:
    """Validate days back parameter."""
    if not isinstance(days, int) or days < 1 or days > 365:
        raise ValueError("Days back must be an integer between 1 and 365")
    return days


def validate_config(config: Config) -> None:
    """Validate a complete configuration object."""
    # Validate GitHub token
    if not validate_github_token(config.github_token):
        raise ValueError("Invalid GitHub token format")
    
    # Validate organization name if provided
    if config.organization and not validate_organization_name(config.organization):
        raise ValueError("Invalid GitHub organization name")
    
    # Validate that either organization or enterprise is provided
    if not config.organization and not config.enterprise:
        raise ValueError("Either organization or enterprise must be specified")
    
    if config.organization and config.enterprise:
        raise ValueError("Organization and enterprise are mutually exclusive")
    
    # Validate report types and formats are already handled by Pydantic validators
    # in the Config class, but we can add additional checks here if needed