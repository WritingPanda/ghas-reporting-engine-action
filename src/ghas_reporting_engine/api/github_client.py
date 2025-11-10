"""
GitHub API client for fetching GHAS alerts.

This module provides a client for interacting with the GitHub REST API
to fetch Advanced Security alerts from organizations and enterprises.
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import Config
from .models import Alert

logger = logging.getLogger(__name__)


class GitHubAPIError(Exception):
    """Exception raised for GitHub API errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class GitHubClient:
    """Client for interacting with the GitHub API."""

    def __init__(self, config: Config):
        """Initialize the GitHub client."""
        self.config = config
        self.session = self._create_session()
        self.base_url = config.api_base_url

        # Validate token and get user info
        self._validate_token()

    def _create_session(self) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()

        # Set headers
        session.headers.update(
            {
                "Authorization": f"token {self.config.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "ghas-reporting-engine/0.1.0",
            }
        )

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _validate_token(self) -> None:
        """Validate the GitHub token and get user information."""
        try:
            response = self._make_request("GET", "/user")
            user_data = response.json()
            logger.info(f"Authenticated as: {user_data.get('login')}")
        except GitHubAPIError as e:
            if e.status_code == 401:
                raise GitHubAPIError("Invalid GitHub token provided") from e
            raise

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Make a request to the GitHub API."""
        url = urljoin(self.base_url, endpoint.lstrip("/"))

        logger.debug(f"Making {method} request to {url}")
        if params:
            logger.debug(f"Parameters: {params}")

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                timeout=self.config.request_timeout,
            )

            # Handle rate limiting
            if response.status_code == 429:
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                current_time = int(time.time())
                sleep_time = max(reset_time - current_time + 1, 60)  # At least 1 minute

                logger.warning(f"Rate limited. Sleeping for {sleep_time} seconds...")
                time.sleep(sleep_time)

                # Retry the request
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data,
                    timeout=self.config.request_timeout,
                )

            # Check for errors
            if not response.ok:
                error_data: Dict[str, Any] = {}
                try:
                    error_data = response.json()
                except Exception:
                    pass

                error_message = error_data.get("message", f"HTTP {response.status_code}")
                raise GitHubAPIError(
                    message=f"GitHub API error: {error_message}",
                    status_code=response.status_code,
                    response_data=error_data,
                )

            # Log rate limit info
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining:
                logger.debug(f"Rate limit remaining: {remaining}")

            return response

        except requests.RequestException as e:
            raise GitHubAPIError(f"Request failed: {str(e)}") from e

    def _paginate_alerts(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Paginate through alert results."""
        all_alerts = []
        page = 1
        per_page = 100  # Maximum allowed by GitHub API

        if params is None:
            params = {}

        # Add date filters
        params.update(
            {
                "per_page": per_page,
                "sort": "created",
                "direction": "desc",
            }
        )

        # Add state filter
        states = ["open"]
        if self.config.include_dismissed:
            states.append("dismissed")

        while True:
            params["page"] = page

            logger.debug(f"Fetching page {page} of alerts...")

            response = self._make_request("GET", endpoint, params=params)
            alerts_data = response.json()

            if not alerts_data:
                break

            # Filter by date range
            filtered_alerts = []
            for alert_data in alerts_data:
                created_at = alert_data.get("created_at")
                if created_at:
                    # Parse ISO format datetime and ensure it's timezone-aware
                    alert_date = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    if self.config.since_date <= alert_date <= self.config.until_date:
                        filtered_alerts.append(alert_data)

            all_alerts.extend(filtered_alerts)

            # If we got fewer than per_page results, we're done
            if len(alerts_data) < per_page:
                break

            page += 1

            # Add a small delay to be respectful to the API
            time.sleep(0.1)

        logger.info(f"Fetched {len(all_alerts)} alerts total")
        return all_alerts

    def fetch_organization_alerts(self, org_name: str) -> List[Alert]:
        """Fetch alerts for a GitHub organization."""
        logger.info(f"Fetching alerts for organization: {org_name}")

        endpoint = f"/orgs/{org_name}/code-scanning/alerts"
        alerts_data = self._paginate_alerts(endpoint)

        return self._parse_alerts(alerts_data)

    def fetch_enterprise_alerts(self, enterprise_name: str) -> List[Alert]:
        """Fetch alerts for a GitHub enterprise."""
        logger.info(f"Fetching alerts for enterprise: {enterprise_name}")

        # Note: Enterprise-level alerts require different API endpoints
        # This is a simplified implementation - in practice, you might need
        # to fetch alerts from all organizations in the enterprise
        endpoint = f"/enterprises/{enterprise_name}/code-scanning/alerts"

        try:
            alerts_data = self._paginate_alerts(endpoint)
            return self._parse_alerts(alerts_data)
        except GitHubAPIError as e:
            if e.status_code == 404:
                # Fallback: try to get organizations and fetch from each
                logger.warning("Enterprise endpoint not available, trying organization fallback")
                return self._fetch_enterprise_via_orgs(enterprise_name)
            raise

    def _fetch_enterprise_via_orgs(self, enterprise_name: str) -> List[Alert]:
        """Fetch enterprise alerts by getting all organizations."""
        # This is a simplified fallback - in practice, you'd need proper enterprise API access
        logger.warning("Enterprise API not fully implemented - using organization fallback")
        return []

    def fetch_alerts(self) -> List[Alert]:
        """Fetch alerts based on configuration."""
        if self.config.organization:
            alerts = self.fetch_organization_alerts(self.config.organization)
        elif self.config.enterprise:
            alerts = self.fetch_enterprise_alerts(self.config.enterprise)
        else:
            raise ValueError("Neither organization nor enterprise specified")

        # Filter by severity if specified
        if self.config.severity_filters:
            original_count = len(alerts)
            alerts = [
                alert for alert in alerts if alert.severity_level in self.config.severity_filters
            ]
            logger.info(f"Filtered {original_count} alerts to {len(alerts)} by severity")

        return alerts

    def _parse_alerts(self, alerts_data: List[Dict[str, Any]]) -> List[Alert]:
        """Parse raw alert data into Alert objects."""
        alerts = []

        for alert_data in alerts_data:
            try:
                alert = Alert(**alert_data)
                alerts.append(alert)
            except Exception as e:
                logger.warning(f"Failed to parse alert {alert_data.get('number', 'unknown')}: {e}")
                continue

        logger.info(f"Successfully parsed {len(alerts)} alerts")
        return alerts
