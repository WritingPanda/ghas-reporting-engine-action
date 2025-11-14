"""
Configuration management for GHAS Reporting Engine.

This module handles configuration settings and validation for the application.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Config(BaseModel):
    """Configuration model for GHAS Reporting Engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # GitHub settings
    github_token: str = Field(..., description="GitHub API token")
    organization: Optional[str] = Field(None, description="GitHub organization name")
    enterprise: Optional[str] = Field(None, description="GitHub enterprise name")

    # Report settings
    report_types: List[str] = Field(default=["owasp"], description="Types of reports to generate")
    report_formats: List[str] = Field(default=["json"], description="Output formats for reports")

    # Time settings
    days_back: int = Field(default=30, ge=1, le=365, description="Number of days to look back")

    # Output settings
    output_dir: Path = Field(default=Path("./reports"), description="Output directory for reports")

    # Filter settings
    include_dismissed: bool = Field(default=False, description="Include dismissed alerts")
    severity_filters: Optional[List[str]] = Field(None, description="Filter by severity levels")

    # API settings
    api_base_url: str = Field(default="https://api.github.com", description="GitHub API base URL")
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum API request retries")
    request_timeout: int = Field(
        default=30, ge=5, le=300, description="API request timeout in seconds"
    )

    @field_validator("report_types")
    @classmethod
    def validate_report_types(cls, v: List[str]) -> List[str]:
        """Validate report types."""
        valid_types = {"owasp", "sans", "mitre"}
        invalid_types = set(v) - valid_types
        if invalid_types:
            raise ValueError(f"Invalid report types: {', '.join(invalid_types)}")
        return v

    @field_validator("report_formats")
    @classmethod
    def validate_report_formats(cls, v: List[str]) -> List[str]:
        """Validate report formats."""
        valid_formats = {"json", "csv", "html"}
        invalid_formats = set(v) - valid_formats
        if invalid_formats:
            raise ValueError(f"Invalid report formats: {', '.join(invalid_formats)}")
        return v

    @field_validator("severity_filters")
    @classmethod
    def validate_severity_filters(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate severity filters."""
        if v is None:
            return v

        valid_severities = {"critical", "high", "medium", "low"}
        invalid_severities = set(v) - valid_severities
        if invalid_severities:
            raise ValueError(f"Invalid severity filters: {', '.join(invalid_severities)}")
        return v

    @property
    def target_name(self) -> str:
        """Get the target name (organization or enterprise)."""
        return self.organization or self.enterprise or "unknown"

    @property
    def target_type(self) -> str:
        """Get the target type."""
        if self.organization:
            return "organization"
        elif self.enterprise:
            return "enterprise"
        else:
            return "unknown"

    @property
    def since_date(self) -> datetime:
        """Get the start date for alert fetching."""
        return datetime.now(timezone.utc) - timedelta(days=self.days_back)

    @property
    def until_date(self) -> datetime:
        """Get the end date for alert fetching."""
        return datetime.now(timezone.utc)

    def get_report_filename(self, report_type: str, format_type: str) -> str:
        """Generate a filename for a report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"ghas_{report_type}_{self.target_name}_{timestamp}.{format_type}"

    def get_report_path(self, report_type: str, format_type: str) -> Path:
        """Get the full path for a report file."""
        filename = self.get_report_filename(report_type, format_type)
        return self.output_dir / filename
