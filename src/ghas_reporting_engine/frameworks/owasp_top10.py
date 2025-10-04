"""
OWASP Top 10 specific processing and analysis.

This module provides OWASP Top 10 2021 specific processing and insights
for GitHub Advanced Security alerts.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict

from ..api.models import Alert
from ..processors.cwe_mapper import CWEMapper
from ..utils.logger import get_logger


logger = get_logger("owasp_processor")


class OWASPTop10Processor:
    """Processor for OWASP Top 10 2021 analysis."""
    
    def __init__(self):
        """Initialize the OWASP processor."""
        self.cwe_mapper = CWEMapper()
        self.category_descriptions = {
            "A01:2021 - Broken Access Control": {
                "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
                "prevention": [
                    "Implement proper access control mechanisms",
                    "Use deny by default principle",
                    "Implement proper session management",
                    "Rate limit API and controller access"
                ]
            },
            "A02:2021 - Cryptographic Failures": {
                "description": "Many web applications and APIs do not properly protect sensitive data.",
                "prevention": [
                    "Use strong encryption algorithms",
                    "Implement proper key management",
                    "Use secure protocols (HTTPS, TLS)",
                    "Avoid storing sensitive data unnecessarily"
                ]
            },
            "A03:2021 - Injection": {
                "description": "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application.",
                "prevention": [
                    "Use parameterized queries",
                    "Validate and sanitize all inputs",
                    "Use safe APIs that avoid interpreters",
                    "Implement proper input validation"
                ]
            },
            "A04:2021 - Insecure Design": {
                "description": "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design.'",
                "prevention": [
                    "Implement secure development lifecycle",
                    "Use threat modeling",
                    "Design security controls from the start",
                    "Regular security architecture reviews"
                ]
            },
            "A05:2021 - Security Misconfiguration": {
                "description": "The application might be vulnerable if the application is missing appropriate security hardening across any part of the application stack.",
                "prevention": [
                    "Implement secure configuration management",
                    "Remove unnecessary features and frameworks",
                    "Keep software updated",
                    "Regular security configuration reviews"
                ]
            },
            "A06:2021 - Vulnerable and Outdated Components": {
                "description": "You are likely vulnerable if you do not know the versions of all components you use.",
                "prevention": [
                    "Maintain inventory of all components",
                    "Monitor for vulnerabilities",
                    "Keep components updated",
                    "Use dependency scanning tools"
                ]
            },
            "A07:2021 - Identification and Authentication Failures": {
                "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
                "prevention": [
                    "Implement multi-factor authentication",
                    "Use strong session management",
                    "Implement proper password policies",
                    "Protect against brute force attacks"
                ]
            },
            "A08:2021 - Software and Data Integrity Failures": {
                "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
                "prevention": [
                    "Use digital signatures for software updates",
                    "Implement CI/CD pipeline security",
                    "Verify integrity of libraries and dependencies",
                    "Use secure deserialization practices"
                ]
            },
            "A09:2021 - Security Logging and Monitoring Failures": {
                "description": "This category is to help detect, escalate, and respond to active breaches.",
                "prevention": [
                    "Implement comprehensive logging",
                    "Monitor for suspicious activities",
                    "Establish incident response procedures",
                    "Regular log analysis and alerting"
                ]
            },
            "A10:2021 - Server-Side Request Forgery (SSRF)": {
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
                "prevention": [
                    "Validate and sanitize all user input",
                    "Use allowlists for URLs",
                    "Implement network segmentation",
                    "Disable HTTP redirections"
                ]
            }
        }
    
    def process(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Process alerts for OWASP Top 10 analysis."""
        logger.info(f"Processing {len(alerts)} alerts for OWASP Top 10 analysis")
        
        # Extract all CWEs
        all_cwes = set()
        for alert in alerts:
            all_cwes.update(alert.cwes)
        
        # Get OWASP mappings
        owasp_mappings = self.cwe_mapper.get_owasp_mappings(list(all_cwes))
        
        # Analyze alerts by category
        category_analysis = self._analyze_by_category(alerts, owasp_mappings)
        
        # Generate insights
        insights = self._generate_insights(category_analysis, alerts)
        
        # Calculate risk scores
        risk_scores = self._calculate_risk_scores(category_analysis)
        
        return {
            "framework": "OWASP Top 10 2021",
            "total_alerts": len(alerts),
            "mapped_alerts": sum(cat["alert_count"] for cat in category_analysis.values()),
            "categories": category_analysis,
            "insights": insights,
            "risk_scores": risk_scores,
            "recommendations": self._generate_recommendations(category_analysis),
        }
    
    def _analyze_by_category(self, alerts: List[Alert], mappings: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze alerts by OWASP category."""
        category_analysis = {}
        
        for category, mapped_cwes in mappings.items():
            # Find alerts that match this category
            category_alerts = []
            for alert in alerts:
                if any(cwe in alert.cwes for cwe in mapped_cwes):
                    category_alerts.append(alert)
            
            if not category_alerts:
                continue
            
            # Analyze this category
            severity_dist = defaultdict(int)
            state_dist = defaultdict(int)
            repo_dist = defaultdict(int)
            rule_dist = defaultdict(int)
            
            for alert in category_alerts:
                severity_dist[alert.severity_level] += 1
                state_dist[alert.state] += 1
                repo_dist[alert.repository.full_name] += 1
                rule_dist[alert.rule.id] += 1
            
            category_analysis[category] = {
                "alert_count": len(category_alerts),
                "mapped_cwes": mapped_cwes,
                "severity_distribution": dict(severity_dist),
                "state_distribution": dict(state_dist),
                "top_repositories": dict(sorted(repo_dist.items(), key=lambda x: x[1], reverse=True)[:5]),
                "top_rules": dict(sorted(rule_dist.items(), key=lambda x: x[1], reverse=True)[:5]),
                "description": self.category_descriptions.get(category, {}).get("description", ""),
                "prevention_tips": self.category_descriptions.get(category, {}).get("prevention", []),
            }
        
        return category_analysis
    
    def _generate_insights(self, category_analysis: Dict[str, Any], alerts: List[Alert]) -> List[str]:
        """Generate insights about OWASP findings."""
        insights = []
        
        if not category_analysis:
            insights.append("No alerts mapped to OWASP Top 10 categories.")
            return insights
        
        # Most problematic category
        top_category = max(category_analysis.items(), key=lambda x: x[1]["alert_count"])
        insights.append(
            f"Most problematic OWASP category: {top_category[0]} with {top_category[1]['alert_count']} alerts"
        )
        
        # Coverage analysis
        total_categories = 10
        covered_categories = len(category_analysis)
        coverage_percent = (covered_categories / total_categories) * 100
        insights.append(
            f"OWASP Top 10 coverage: {covered_categories}/{total_categories} categories ({coverage_percent:.1f}%)"
        )
        
        # Severity analysis
        critical_categories = []
        high_categories = []
        
        for category, data in category_analysis.items():
            critical_count = data["severity_distribution"].get("critical", 0)
            high_count = data["severity_distribution"].get("high", 0)
            
            if critical_count > 0:
                critical_categories.append((category, critical_count))
            if high_count > 0:
                high_categories.append((category, high_count))
        
        if critical_categories:
            insights.append(
                f"Categories with critical vulnerabilities: {len(critical_categories)}"
            )
        
        if high_categories:
            insights.append(
                f"Categories with high severity vulnerabilities: {len(high_categories)}"
            )
        
        # State analysis
        total_open = sum(data["state_distribution"].get("open", 0) for data in category_analysis.values())
        total_mapped = sum(data["alert_count"] for data in category_analysis.values())
        
        if total_mapped > 0:
            open_percent = (total_open / total_mapped) * 100
            insights.append(
                f"{open_percent:.1f}% of OWASP-mapped alerts are still open"
            )
        
        return insights
    
    def _calculate_risk_scores(self, category_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Calculate risk scores for each OWASP category."""
        risk_scores = {}
        
        severity_weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
        }
        
        state_weights = {
            "open": 1.0,
            "dismissed": 0.3,
            "fixed": 0.0,
        }
        
        for category, data in category_analysis.items():
            score = 0.0
            total_alerts = data["alert_count"]
            
            if total_alerts == 0:
                risk_scores[category] = 0.0
                continue
            
            # Calculate weighted score based on severity and state
            for severity, count in data["severity_distribution"].items():
                severity_weight = severity_weights.get(severity, 1.0)
                
                # Assume proportional state distribution for this severity
                for state, state_count in data["state_distribution"].items():
                    state_weight = state_weights.get(state, 1.0)
                    proportion = state_count / sum(data["state_distribution"].values())
                    score += count * severity_weight * state_weight * proportion
            
            # Normalize to 0-10 scale
            max_possible_score = total_alerts * 4.0 * 1.0  # All critical and open
            normalized_score = (score / max_possible_score) * 10.0 if max_possible_score > 0 else 0.0
            
            risk_scores[category] = round(normalized_score, 2)
        
        return risk_scores
    
    def _generate_recommendations(self, category_analysis: Dict[str, Any]) -> List[str]:
        """Generate OWASP-specific recommendations."""
        recommendations = []
        
        if not category_analysis:
            recommendations.append("No OWASP Top 10 issues identified in the current analysis.")
            return recommendations
        
        # Sort categories by alert count
        sorted_categories = sorted(
            category_analysis.items(),
            key=lambda x: x[1]["alert_count"],
            reverse=True
        )
        
        # Recommendations for top 3 categories
        for i, (category, data) in enumerate(sorted_categories[:3]):
            critical_count = data["severity_distribution"].get("critical", 0)
            high_count = data["severity_distribution"].get("high", 0)
            open_count = data["state_distribution"].get("open", 0)
            
            if critical_count > 0 or high_count > 0:
                recommendations.append(
                    f"Priority {i+1}: Address {category} - {critical_count + high_count} "
                    f"critical/high severity issues found"
                )
        
        # Repository-specific recommendations
        all_repos = set()
        for data in category_analysis.values():
            all_repos.update(data["top_repositories"].keys())
        
        if len(all_repos) > 1:
            recommendations.append(
                f"Consider implementing organization-wide security policies across {len(all_repos)} repositories"
            )
        
        # Prevention recommendations
        recommendations.append(
            "Implement OWASP secure coding practices and regular security training for developers"
        )
        
        return recommendations