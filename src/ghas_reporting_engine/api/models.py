"""
Data models for GitHub API responses.

This module defines Pydantic models for GitHub Advanced Security API responses.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class Repository(BaseModel):
    """GitHub repository model."""

    id: int
    name: str
    full_name: str
    private: bool
    html_url: str
    description: Optional[str] = None


class User(BaseModel):
    """GitHub user model."""

    login: str
    id: int
    avatar_url: str
    html_url: str
    type: str


class Rule(BaseModel):
    """CodeQL rule model."""

    id: str
    severity: str
    tags: List[str] = Field(default_factory=list)
    description: str
    name: str
    security_severity_level: Optional[str] = None


class Tool(BaseModel):
    """Analysis tool model."""

    name: str
    guid: Optional[str] = None
    version: Optional[str] = None


class Location(BaseModel):
    """Alert location model."""

    path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int


class Message(BaseModel):
    """Alert message model."""

    text: str


class Instance(BaseModel):
    """Alert instance model."""

    ref: str
    analysis_key: str
    category: str
    environment: str
    state: str
    commit_sha: str
    message: Message
    location: Location
    classifications: List[str] = Field(default_factory=list)


class Alert(BaseModel):
    """GitHub Advanced Security alert model."""

    number: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    url: str
    html_url: str
    state: str
    dismissed_by: Optional[User] = None
    dismissed_at: Optional[datetime] = None
    dismissed_reason: Optional[str] = None
    dismissed_comment: Optional[str] = None
    rule: Rule
    tool: Tool
    most_recent_instance: Instance
    instances_url: str
    repository: Repository

    @property
    def cwes(self) -> List[str]:
        """Extract CWE identifiers from rule tags."""
        cwes = []
        for tag in self.rule.tags:
            if tag.startswith("external/cwe/"):
                cwe = tag.replace("external/cwe/", "").upper()
                if not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe}"
                cwes.append(cwe)
        return cwes

    @property
    def severity_level(self) -> str:
        """Get the severity level (normalized)."""
        # Use security_severity_level if available, otherwise fall back to severity
        severity = self.rule.security_severity_level or self.rule.severity
        return severity.lower()

    @property
    def is_dismissed(self) -> bool:
        """Check if the alert is dismissed."""
        return self.state == "dismissed"

    @property
    def is_open(self) -> bool:
        """Check if the alert is open."""
        return self.state == "open"

    @property
    def is_fixed(self) -> bool:
        """Check if the alert is fixed."""
        return self.state == "fixed"
