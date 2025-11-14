"""Reporter-related unit tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghas_reporting_engine.config import Config
from ghas_reporting_engine.processors.data_analyzer import AnalysisResult
from ghas_reporting_engine.reports.html_reporter import HTMLReporter
from ghas_reporting_engine.reports.json_reporter import JSONReporter


@pytest.fixture
def analysis_result() -> AnalysisResult:
    result = AnalysisResult()
    active_alert = {
        "repository": "example/repo",
        "number": 42,
        "rule_id": "js/sql-injection",
        "rule_name": "SQL Injection",
        "severity": "high",
        "state": "open",
        "created_at": "2025-01-01T00:00:00Z",
        "html_url": "https://github.com/example/repo/code-scanning/42",
        "cwes": ["CWE-89"],
    }
    result.summary.update(
        {
            "total_alerts": 5,
            "open_alerts": 3,
            "dismissed_alerts": 1,
            "fixed_alerts": 1,
        }
    )
    result.severity_analysis = {
        "severity_counts": {"critical": 1, "high": 2, "medium": 1, "low": 1},
        "severity_percentages": {"critical": 20.0, "high": 40.0, "medium": 20.0, "low": 20.0},
        "critical_and_high": 3,
        "medium_and_low": 2,
    }
    result.cwe_analysis = {
        "total_unique_cwes": 2,
        "top_cwes": {"CWE-79": 2, "CWE-89": 1},
        "cwe_details": {},
    }
    result.repository_analysis = {
        "total_repositories": 1,
        "repository_details": {
            "example/repo": {
                "total_alerts": 5,
                "unique_cwes": 2,
                "unique_rules": 2,
                "severity_distribution": {"high": 2},
                "state_distribution": {"open": 3},
                "active_alerts": [active_alert],
                "active_alert_count": 1,
            }
        },
        "top_repositories_by_alerts": {"example/repo": 5},
        "active_alerts_by_repository": {"example/repo": [active_alert]},
    }
    result.active_alerts_by_repository = result.repository_analysis["active_alerts_by_repository"]
    result.trend_analysis = {"daily_counts": {"2025-01-01": 5}}
    result.unmapped_cwes = ["CWE-999"]
    result.recommendations = ["Fix critical items first"]
    result.framework_mappings = {
        "owasp": {
            "summary": {"description": "OWASP summary"},
            "category_alerts": {"A01": 2},
            "total_mapped_alerts": 2,
        },
        "sans": {
            "summary": {"description": "SANS summary"},
            "mappings": {"CWE-79": {"rank": 2}},
            "cwe_counts": {"CWE-79": 1},
            "total_mapped_alerts": 1,
        },
    }
    return result


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        github_token="token",
        organization="example",
        enterprise=None,
        report_types=["owasp", "sans"],
        report_formats=["json", "html"],
        days_back=30,
        output_dir=tmp_path,
        include_dismissed=False,
        severity_filters=None,
    )


def test_json_reporter_generates_one_file_per_framework(config: Config, analysis_result: AnalysisResult) -> None:
    reporter = JSONReporter(config)

    paths = reporter.generate_reports(analysis_result)

    assert len(paths) == len(config.report_types)

    seen_frameworks = set()
    for path in paths:
        data = json.loads(path.read_text())
        framework = data["metadata"]["framework"]
        seen_frameworks.add(framework)
        assert data["framework_mapping"] == analysis_result.framework_mappings[framework]
        assert data["metadata"]["frameworks_requested"] == config.report_types
        assert data["active_alerts_by_repository"]["example/repo"][0]["number"] == 42

    assert seen_frameworks == set(config.report_types)


def test_html_reporter_inlines_css_and_scopes_framework(config: Config, analysis_result: AnalysisResult) -> None:
    single_framework_config = config.model_copy(update={"report_types": ["owasp"], "report_formats": ["html"]})
    reporter = HTMLReporter(single_framework_config)

    paths = reporter.generate_reports(analysis_result)
    assert len(paths) == 1

    html = paths[0].read_text()
    assert "<style" in html and ".container" in html
    assert "OWASP Top 10 2021" in html
    assert "SANS Top 25" not in html
    assert "Active Alerts by Repository" in html
    assert "SQL Injection" in html