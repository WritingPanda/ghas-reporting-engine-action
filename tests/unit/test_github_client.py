"""Tests for the GitHub client module."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

from ghas_reporting_engine.api.github_client import GitHubAPIError, GitHubClient
from ghas_reporting_engine.config import Config


class FakeResponse:
    """Simple stand-in for requests.Response in unit tests."""

    def __init__(self, payload: Any):
        self._payload = payload
        self.ok = True
        self.status_code = 200
        self.headers: Dict[str, str] = {}

    def json(self) -> Any:
        return self._payload


def _build_alert_payload(state: str = "open") -> Dict[str, Any]:
    """Build a minimal alert payload that satisfies the Pydantic model."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "number": 1,
        "created_at": now,
        "updated_at": now,
        "url": "https://api.github.com/repos/example/repo/code-scanning/alerts/1",
        "html_url": "https://github.com/example/repo/code-scanning/1",
        "state": state,
        "dismissed_by": None,
        "dismissed_at": None,
        "dismissed_reason": None,
        "dismissed_comment": None,
        "rule": {
            "id": "test/rule",
            "severity": "error",
            "tags": ["security", "external/cwe/cwe-079"],
            "description": "Rule description",
            "name": "test/rule",
            "security_severity_level": "high",
        },
        "tool": {"name": "CodeQL", "guid": None, "version": "2.0"},
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "analysis_key": "workflow:build",
            "category": "workflow:build",
            "environment": "{}",
            "state": state,
            "commit_sha": "deadbeef",
            "message": {"text": "Example"},
            "location": {
                "path": "src/app.py",
                "start_line": 1,
                "end_line": 1,
                "start_column": 1,
                "end_column": 5,
            },
            "classifications": [],
        },
        "instances_url": "https://api.github.com/repos/example/repo/code-scanning/alerts/1/instances",
        "repository": {
            "id": 100,
            "name": "repo",
            "full_name": "example/repo",
            "private": False,
            "html_url": "https://github.com/example/repo",
            "description": "",
        },
    }


@pytest.fixture
def org_config(tmp_path: Path) -> Config:
    return Config(
        github_token="token",
        organization="example",
        enterprise=None,
        report_types=["owasp"],
        report_formats=["json"],
        days_back=30,
        output_dir=tmp_path,
        include_dismissed=True,
        severity_filters=None,
    )


@pytest.fixture
def enterprise_config(tmp_path: Path) -> Config:
    return Config(
        github_token="token",
        organization=None,
        enterprise="example-ent",
        report_types=["owasp"],
        report_formats=["json"],
        days_back=30,
        output_dir=tmp_path,
        include_dismissed=False,
        severity_filters=None,
    )


def test_fetch_org_alerts_request_includes_dismissed_state(mocker, org_config: Config) -> None:
    mocker.patch.object(GitHubClient, "_validate_token", return_value=None)
    client = GitHubClient(org_config)

    params_seen: List[Dict[str, Any]] = []

    def fake_request(method: str, endpoint: str, params=None, data=None):  # type: ignore[override]
        if endpoint.startswith("/orgs/") and "code-scanning" in endpoint:
            params_seen.append(dict(params or {}))
            page = params.get("page") if params else 1
            if page == 1:
                return FakeResponse([_build_alert_payload()])
            return FakeResponse([])
        raise AssertionError("Unexpected endpoint requested")

    client._make_request = mocker.Mock(side_effect=fake_request)

    alerts = client.fetch_organization_alerts("example")

    assert params_seen, "Expected at least one API call"
    assert params_seen[0]["state"] == "open,dismissed"
    assert len(alerts) == 1


def test_fetch_enterprise_alerts_falls_back_to_orgs(mocker, enterprise_config: Config) -> None:
    mocker.patch.object(GitHubClient, "_validate_token", return_value=None)
    client = GitHubClient(enterprise_config)

    client._paginate_alerts = mocker.Mock(side_effect=GitHubAPIError("missing", status_code=404))
    fallback_mock = mocker.Mock(return_value=["alert"])
    client._fetch_enterprise_via_orgs = fallback_mock

    alerts = client.fetch_enterprise_alerts("example-ent")

    assert alerts == ["alert"]
    fallback_mock.assert_called_once_with("example-ent")


def test_fetch_enterprise_via_orgs_aggregates_org_alerts(mocker, enterprise_config: Config) -> None:
    mocker.patch.object(GitHubClient, "_validate_token", return_value=None)
    client = GitHubClient(enterprise_config)

    mocker.patch.object(client, "_list_enterprise_orgs", return_value=["org-a", "org-b"])
    fetch_mock = mocker.Mock(side_effect=[[f"alert-{idx}"] for idx in range(2)])
    client.fetch_organization_alerts = fetch_mock

    alerts = client._fetch_enterprise_via_orgs("example-ent")

    assert alerts == ["alert-0", "alert-1"]
    fetch_mock.assert_has_calls(
        [mocker.call("org-a"), mocker.call("org-b")]
    )