"""
Data analysis engine for GHAS alerts.

This module provides comprehensive analysis of GitHub Advanced Security alerts,
including mapping to compliance frameworks and generating insights.
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

from ..api.models import Alert
from ..config import Config
from ..utils.logger import get_logger
from .cwe_mapper import CWEMapper

logger = get_logger("data_analyzer")


class AnalysisResult:
    """Container for analysis results."""

    def __init__(self) -> None:
        self.summary: Dict[str, Any] = {
            "total_alerts": 0,
            "open_alerts": 0,
            "dismissed_alerts": 0,
            "fixed_alerts": 0,
        }
        self.framework_mappings: Dict[str, Any] = {}
        self.cwe_analysis: Dict[str, Any] = {}
        self.repository_analysis: Dict[str, Any] = {}
        self.trend_analysis: Dict[str, Any] = {}
        self.severity_analysis: Dict[str, Any] = {}
        self.unmapped_cwes: List[str] = []
        self.recommendations: List[str] = []


class DataAnalyzer:
    """Analyzes GHAS alert data and maps to compliance frameworks."""

    def __init__(self, config: Config):
        """Initialize the data analyzer."""
        self.config = config
        self.cwe_mapper = CWEMapper()

    def analyze(self, alerts: List[Alert]) -> AnalysisResult:
        """Perform comprehensive analysis of alerts."""
        logger.info(f"Starting analysis of {len(alerts)} alerts")

        result = AnalysisResult()

        if not alerts:
            logger.warning("No alerts to analyze")
            return result

        # Basic summary analysis
        result.summary = self._analyze_summary(alerts)

        # Extract all unique CWEs
        all_cwes = self._extract_cwes(alerts)
        logger.info(f"Found {len(all_cwes)} unique CWEs")

        # Framework mappings
        result.framework_mappings = self._analyze_frameworks(alerts, all_cwes)

        # CWE analysis
        result.cwe_analysis = self._analyze_cwes(alerts, all_cwes)

        # Repository analysis
        result.repository_analysis = self._analyze_repositories(alerts)

        # Severity analysis
        result.severity_analysis = self._analyze_severity(alerts)

        # Trend analysis
        result.trend_analysis = self._analyze_trends(alerts)

        # Find unmapped CWEs
        result.unmapped_cwes = self.cwe_mapper.get_unmapped_cwes(list(all_cwes))

        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)

        logger.info("Analysis completed successfully")
        return result

    def _analyze_summary(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Generate basic summary statistics."""
        summary = {
            "total_alerts": len(alerts),
            "open_alerts": sum(1 for alert in alerts if alert.is_open),
            "dismissed_alerts": sum(1 for alert in alerts if alert.is_dismissed),
            "fixed_alerts": sum(1 for alert in alerts if alert.is_fixed),
        }

        return summary

    def _extract_cwes(self, alerts: List[Alert]) -> set:
        """Extract all unique CWEs from alerts."""
        all_cwes = set()
        for alert in alerts:
            all_cwes.update(alert.cwes)
        return all_cwes

    def _analyze_frameworks(self, alerts: List[Alert], all_cwes: set) -> Dict[str, Any]:
        """Analyze alerts against compliance frameworks."""
        framework_analysis = {}

        # Get mappings for requested frameworks
        for framework in self.config.report_types:
            logger.debug(f"Analyzing {framework} framework mappings")

            if framework == "owasp":
                framework_analysis["owasp"] = self._analyze_owasp(alerts, all_cwes)
            elif framework == "sans":
                framework_analysis["sans"] = self._analyze_sans(alerts, all_cwes)
            elif framework == "mitre":
                framework_analysis["mitre"] = self._analyze_mitre_kev(alerts, all_cwes)

        return framework_analysis

    def _analyze_owasp(self, alerts: List[Alert], all_cwes: set) -> Dict[str, Any]:
        """Analyze alerts against OWASP Top 10."""
        owasp_mappings = self.cwe_mapper.get_owasp_mappings(list(all_cwes))

        # Count alerts per OWASP category
        category_counts = defaultdict(int)
        category_alerts = defaultdict(list)

        for alert in alerts:
            for category, mapped_cwes in owasp_mappings.items():
                if any(cwe in alert.cwes for cwe in mapped_cwes):
                    category_counts[category] += 1
                    category_alerts[category].append(alert)

        return {
            "summary": self.cwe_mapper.get_framework_summary("owasp"),
            "mappings": owasp_mappings,
            "category_counts": dict(category_counts),
            "category_alerts": {k: len(v) for k, v in category_alerts.items()},
            "total_mapped_alerts": sum(category_counts.values()),
        }

    def _analyze_sans(self, alerts: List[Alert], all_cwes: set) -> Dict[str, Any]:
        """Analyze alerts against SANS Top 25."""
        sans_mappings = self.cwe_mapper.get_sans_mappings(list(all_cwes))

        # Count alerts per SANS CWE
        sans_counts = defaultdict(int)
        sans_alerts = defaultdict(list)

        for alert in alerts:
            for cwe in alert.cwes:
                if cwe in sans_mappings:
                    sans_counts[cwe] += 1
                    sans_alerts[cwe].append(alert)

        # Sort by SANS ranking
        sorted_counts = sorted(sans_counts.items(), key=lambda x: sans_mappings[x[0]]["rank"])

        return {
            "summary": self.cwe_mapper.get_framework_summary("sans"),
            "mappings": sans_mappings,
            "cwe_counts": dict(sorted_counts),
            "total_mapped_alerts": sum(sans_counts.values()),
            "top_5_cwes": dict(sorted_counts[:5]),
        }

    def _analyze_mitre_kev(self, alerts: List[Alert], all_cwes: set) -> Dict[str, Any]:
        """Analyze alerts against MITRE KEV."""
        kev_mappings = self.cwe_mapper.get_mitre_kev_mappings(list(all_cwes))

        # Count alerts per KEV CWE
        kev_counts = defaultdict(int)
        kev_alerts = defaultdict(list)

        for alert in alerts:
            for cwe in alert.cwes:
                if cwe in kev_mappings:
                    kev_counts[cwe] += 1
                    kev_alerts[cwe].append(alert)

        # Sort by MITRE KEV ranking
        sorted_counts = sorted(kev_counts.items(), key=lambda x: kev_mappings[x[0]]["rank"])

        return {
            "summary": self.cwe_mapper.get_framework_summary("mitre"),
            "mappings": kev_mappings,
            "cwe_counts": dict(sorted_counts),
            "total_mapped_alerts": sum(kev_counts.values()),
            "critical_vulnerabilities": dict(sorted_counts),
        }

    def _analyze_cwes(self, alerts: List[Alert], all_cwes: set) -> Dict[str, Any]:
        """Detailed CWE analysis."""
        cwe_details: Dict[str, Any] = {}

        for cwe in all_cwes:
            cwe_alerts = [alert for alert in alerts if cwe in alert.cwes]

            severity_dist = Counter(alert.severity_level for alert in cwe_alerts)
            state_dist = Counter(alert.state for alert in cwe_alerts)
            repo_dist = Counter(alert.repository.full_name for alert in cwe_alerts)

            cwe_details[cwe] = {
                "total_alerts": len(cwe_alerts),
                "severity_distribution": dict(severity_dist),
                "state_distribution": dict(state_dist),
                "top_repositories": dict(repo_dist.most_common(5)),
                "first_seen": min(alert.created_at for alert in cwe_alerts) if cwe_alerts else None,
                "last_seen": max(alert.created_at for alert in cwe_alerts) if cwe_alerts else None,
            }

        return {
            "total_unique_cwes": len(all_cwes),
            "cwe_details": cwe_details,
            "top_cwes": dict(Counter(cwe for alert in alerts for cwe in alert.cwes).most_common(10)),
        }

    def _analyze_repositories(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Analyze alerts by repository."""
        repo_analysis: Dict[str, Any] = defaultdict(
            lambda: {
                "total_alerts": 0,
                "severity_distribution": defaultdict(int),
                "state_distribution": defaultdict(int),
                "unique_cwes": set(),
                "unique_rules": set(),
            }
        )

        for alert in alerts:
            repo_name = alert.repository.full_name
            repo_data = repo_analysis[repo_name]

            repo_data["total_alerts"] += 1
            repo_data["severity_distribution"][alert.severity_level] += 1
            repo_data["state_distribution"][alert.state] += 1
            repo_data["unique_cwes"].update(alert.cwes)
            repo_data["unique_rules"].add(alert.rule.id)

        # Convert sets to counts for JSON serialization
        for repo_data in repo_analysis.values():
            repo_data["unique_cwes"] = len(repo_data["unique_cwes"])
            repo_data["unique_rules"] = len(repo_data["unique_rules"])
            repo_data["severity_distribution"] = dict(repo_data["severity_distribution"])
            repo_data["state_distribution"] = dict(repo_data["state_distribution"])

        return {
            "total_repositories": len(repo_analysis),
            "repository_details": dict(repo_analysis),
            "top_repositories_by_alerts": dict(
                Counter(alert.repository.full_name for alert in alerts).most_common(10)
            ),
        }

    def _analyze_severity(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Analyze alerts by severity."""
        severity_counts = Counter(alert.severity_level for alert in alerts)

        # Calculate percentages
        total = len(alerts)
        severity_percentages = {
            severity: (count / total) * 100 for severity, count in severity_counts.items()
        }

        return {
            "severity_counts": dict(severity_counts),
            "severity_percentages": severity_percentages,
            "critical_and_high": severity_counts.get("critical", 0)
            + severity_counts.get("high", 0),
            "medium_and_low": severity_counts.get("medium", 0) + severity_counts.get("low", 0),
        }

    def _analyze_trends(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Analyze trends in alert creation."""
        if not alerts:
            return {}

        # Group alerts by date
        daily_counts = defaultdict(int)
        for alert in alerts:
            date_key = alert.created_at.date().isoformat()
            daily_counts[date_key] += 1

        # Calculate moving averages (7-day)
        sorted_dates = sorted(daily_counts.keys())
        moving_averages = {}

        for i, date in enumerate(sorted_dates):
            if i >= 6:  # Need at least 7 days
                window = sorted_dates[i - 6 : i + 1]
                avg = sum(daily_counts[d] for d in window) / 7
                moving_averages[date] = round(avg, 2)

        return {
            "daily_counts": dict(daily_counts),
            "moving_averages_7day": moving_averages,
            "total_days": len(daily_counts),
            "average_daily": sum(daily_counts.values()) / len(daily_counts) if daily_counts else 0,
            "peak_day": max(daily_counts.items(), key=lambda x: x[1]) if daily_counts else None,
        }

    def _generate_recommendations(self, result: AnalysisResult) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []

        # High-level recommendations
        if result.summary["total_alerts"] > 100:
            recommendations.append(
                "Consider implementing automated alert triaging to manage the high volume of findings."
            )

        # Severity-based recommendations
        critical_high = result.severity_analysis.get("critical_and_high", 0)
        if critical_high > 0:
            recommendations.append(
                f"Prioritize fixing {critical_high} critical and high severity vulnerabilities immediately."
            )

        # Framework-specific recommendations
        for framework, data in result.framework_mappings.items():
            total_mapped = data.get("total_mapped_alerts", 0)
            if total_mapped > 0:
                framework_name = framework.upper()
                recommendations.append(
                    f"{total_mapped} alerts map to {framework_name} compliance requirements - "
                    f"review for regulatory compliance."
                )

        # Repository recommendations
        repo_analysis = result.repository_analysis
        if repo_analysis.get("total_repositories", 0) > 1:
            top_repos = repo_analysis.get("top_repositories_by_alerts", {})
            if top_repos:
                worst_repo = max(top_repos.items(), key=lambda x: x[1])
                recommendations.append(
                    f"Repository '{worst_repo[0]}' has the most alerts ({worst_repo[1]}) - "
                    f"consider focused security review."
                )

        # Unmapped CWE recommendations
        if result.unmapped_cwes:
            recommendations.append(
                f"{len(result.unmapped_cwes)} CWEs don't map to compliance frameworks - "
                f"consider custom analysis."
            )

        return recommendations
