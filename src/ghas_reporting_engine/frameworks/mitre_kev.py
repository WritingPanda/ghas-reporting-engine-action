"""
MITRE KEV (Known Exploited Vulnerabilities) specific processing and analysis.

This module provides MITRE Top 10 Known Exploited Vulnerabilities
specific processing and insights for GitHub Advanced Security alerts.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict

from ..api.models import Alert
from ..processors.cwe_mapper import CWEMapper
from ..utils.logger import get_logger


logger = get_logger("mitre_processor")


class MITREKEVProcessor:
    """Processor for MITRE KEV analysis."""
    
    def __init__(self):
        """Initialize the MITRE KEV processor."""
        self.cwe_mapper = CWEMapper()
    
    def process(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Process alerts for MITRE KEV analysis."""
        logger.info(f"Processing {len(alerts)} alerts for MITRE KEV analysis")
        
        # Extract all CWEs
        all_cwes = set()
        for alert in alerts:
            all_cwes.update(alert.cwes)
        
        # Get MITRE KEV mappings
        kev_mappings = self.cwe_mapper.get_mitre_kev_mappings(list(all_cwes))
        
        # Analyze alerts by KEV ranking
        kev_analysis = self._analyze_by_kev_ranking(alerts, kev_mappings)
        
        # Generate insights
        insights = self._generate_insights(kev_analysis, alerts)
        
        # Calculate criticality scores
        criticality_scores = self._calculate_criticality_scores(kev_analysis)
        
        return {
            "framework": "MITRE Top 10 Known Exploited Vulnerabilities (KEV)",
            "total_alerts": len(alerts),
            "mapped_alerts": sum(kev["alert_count"] for kev in kev_analysis.values()),
            "kev_rankings": kev_analysis,
            "insights": insights,
            "criticality_scores": criticality_scores,
            "recommendations": self._generate_recommendations(kev_analysis),
        }
    
    def _analyze_by_kev_ranking(self, alerts: List[Alert], mappings: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze alerts by MITRE KEV ranking."""
        kev_analysis = {}
        
        # Group alerts by CWE that maps to MITRE KEV
        for alert in alerts:
            for cwe in alert.cwes:
                if cwe in mappings:
                    kev_info = mappings[cwe]
                    rank = kev_info["rank"]
                    name = kev_info["name"]
                    cve_count = kev_info["cve_count"]
                    
                    if cwe not in kev_analysis:
                        kev_analysis[cwe] = {
                            "cwe": cwe,
                            "rank": rank,
                            "name": name,
                            "cve_count": cve_count,
                            "alert_count": 0,
                            "alerts": [],
                            "severity_distribution": defaultdict(int),
                            "state_distribution": defaultdict(int),
                            "repository_distribution": defaultdict(int),
                            "rule_distribution": defaultdict(int),
                        }
                    
                    analysis = kev_analysis[cwe]
                    analysis["alert_count"] += 1
                    analysis["alerts"].append(alert)
                    analysis["severity_distribution"][alert.severity_level] += 1
                    analysis["state_distribution"][alert.state] += 1
                    analysis["repository_distribution"][alert.repository.full_name] += 1
                    analysis["rule_distribution"][alert.rule.id] += 1
        
        # Convert defaultdicts to regular dicts and remove alert objects for JSON serialization
        for cwe, analysis in kev_analysis.items():
            analysis["severity_distribution"] = dict(analysis["severity_distribution"])
            analysis["state_distribution"] = dict(analysis["state_distribution"])
            analysis["repository_distribution"] = dict(analysis["repository_distribution"])
            analysis["rule_distribution"] = dict(analysis["rule_distribution"])
            
            # Keep only top repositories and rules
            analysis["top_repositories"] = dict(
                sorted(analysis["repository_distribution"].items(), key=lambda x: x[1], reverse=True)[:5]
            )
            analysis["top_rules"] = dict(
                sorted(analysis["rule_distribution"].items(), key=lambda x: x[1], reverse=True)[:5]
            )
            
            # Remove full distributions and alert objects
            del analysis["repository_distribution"]
            del analysis["rule_distribution"]
            del analysis["alerts"]
        
        return kev_analysis
    
    def _generate_insights(self, kev_analysis: Dict[str, Any], alerts: List[Alert]) -> List[str]:
        """Generate insights about MITRE KEV findings."""
        insights = []
        
        if not kev_analysis:
            insights.append("No alerts mapped to MITRE Top 10 KEV CWEs.")
            return insights
        
        # Coverage analysis
        total_kev_cwes = 10  # MITRE Top 10 KEV
        covered_cwes = len(kev_analysis)
        coverage_percent = (covered_cwes / total_kev_cwes) * 100
        insights.append(
            f"MITRE KEV coverage: {covered_cwes}/{total_kev_cwes} CWEs ({coverage_percent:.1f}%)"
        )
        
        # Highest priority KEV CWE
        if kev_analysis:
            top_ranked_cwe = min(kev_analysis.items(), key=lambda x: x[1]["rank"])
            insights.append(
                f"Highest priority KEV CWE found: {top_ranked_cwe[0]} (Rank #{top_ranked_cwe[1]['rank']}) "
                f"with {top_ranked_cwe[1]['alert_count']} alerts and "
                f"{top_ranked_cwe[1]['cve_count']} known exploited CVEs"
            )
        
        # Total exploit potential
        total_exploited_cves = sum(data["cve_count"] for data in kev_analysis.values())
        total_alerts_with_exploits = sum(data["alert_count"] for data in kev_analysis.values())
        insights.append(
            f"Found {total_alerts_with_exploits} alerts across {len(kev_analysis)} CWEs "
            f"with {total_exploited_cves} total known exploited CVEs"
        )
        
        # Critical severity analysis
        critical_kev_alerts = sum(
            data["severity_distribution"].get("critical", 0) 
            for data in kev_analysis.values()
        )
        if critical_kev_alerts > 0:
            insights.append(
                f"{critical_kev_alerts} critical severity alerts found in known exploited vulnerability categories"
            )
        
        # Open vulnerability analysis
        open_kev_alerts = sum(
            data["state_distribution"].get("open", 0) 
            for data in kev_analysis.values()
        )
        if open_kev_alerts > 0:
            open_percent = (open_kev_alerts / total_alerts_with_exploits) * 100
            insights.append(
                f"{open_kev_alerts} ({open_percent:.1f}%) KEV-related alerts are still open - "
                f"immediate attention required"
            )
        
        # High-risk CWEs (top 3 ranks with alerts)
        high_risk_cwes = [
            cwe for cwe, data in kev_analysis.items() 
            if data["rank"] <= 3 and data["alert_count"] > 0
        ]
        if high_risk_cwes:
            insights.append(
                f"Found alerts in {len(high_risk_cwes)} of the top 3 most exploited vulnerability types"
            )
        
        return insights
    
    def _calculate_criticality_scores(self, kev_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Calculate criticality scores for each MITRE KEV CWE."""
        criticality_scores = {}
        
        severity_weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
        }
        
        state_weights = {
            "open": 1.0,
            "dismissed": 0.5,  # Still concerning for KEV
            "fixed": 0.0,
        }
        
        for cwe, data in kev_analysis.items():
            # Base score from KEV ranking (higher rank = higher criticality)
            rank_score = (11 - data["rank"]) / 10.0  # Normalize to 0-1, rank 1 = 1.0, rank 10 = 0.1
            
            # CVE count score (more exploited CVEs = higher criticality)
            max_cve_count = max(d["cve_count"] for d in kev_analysis.values()) if kev_analysis else 1
            cve_score = data["cve_count"] / max_cve_count
            
            # Severity score
            severity_score = 0.0
            total_alerts = data["alert_count"]
            
            if total_alerts > 0:
                for severity, count in data["severity_distribution"].items():
                    severity_weight = severity_weights.get(severity, 1.0)
                    severity_score += (count / total_alerts) * severity_weight
                
                severity_score /= 4.0  # Normalize to 0-1
            
            # State score (how many are still exploitable)
            state_score = 0.0
            if total_alerts > 0:
                for state, count in data["state_distribution"].items():
                    state_weight = state_weights.get(state, 1.0)
                    state_score += (count / total_alerts) * state_weight
            
            # Volume score (logarithmic scale for alert count)
            import math
            volume_score = min(math.log10(total_alerts + 1) / 3.0, 1.0)  # Cap at 1000 alerts
            
            # Combined score (weighted average) - KEV gives more weight to exploitation potential
            combined_score = (
                rank_score * 0.35 +      # 35% weight on KEV ranking
                cve_score * 0.25 +       # 25% weight on CVE count (exploitation evidence)
                severity_score * 0.25 +   # 25% weight on severity
                state_score * 0.10 +      # 10% weight on state
                volume_score * 0.05       # 5% weight on volume
            )
            
            criticality_scores[cwe] = round(combined_score * 10.0, 2)  # Scale to 0-10
        
        return criticality_scores
    
    def _generate_recommendations(self, kev_analysis: Dict[str, Any]) -> List[str]:
        """Generate MITRE KEV-specific recommendations."""
        recommendations = []
        
        if not kev_analysis:
            recommendations.append("No MITRE KEV issues identified - continue monitoring for emerging threats.")
            return recommendations
        
        # Critical immediate actions
        open_kev_alerts = sum(
            data["state_distribution"].get("open", 0) 
            for data in kev_analysis.values()
        )
        
        if open_kev_alerts > 0:
            recommendations.append(
                f"URGENT: {open_kev_alerts} alerts found for vulnerabilities with known active exploits - "
                f"prioritize immediate remediation"
            )
        
        # Sort by KEV ranking (most exploited first) 
        sorted_by_rank = sorted(kev_analysis.items(), key=lambda x: x[1]["rank"])
        
        # Recommendations for top ranked KEV CWEs found
        for i, (cwe, data) in enumerate(sorted_by_rank[:3]):
            open_count = data["state_distribution"].get("open", 0)
            critical_count = data["severity_distribution"].get("critical", 0)
            high_count = data["severity_distribution"].get("high", 0)
            
            recommendation = (
                f"Priority {i+1}: {cwe} (KEV Rank #{data['rank']}) - "
                f"{data['cve_count']} known exploited CVEs, {data['alert_count']} alerts found"
            )
            
            if open_count > 0:
                recommendation += f" ({open_count} still open)"
            
            recommendations.append(recommendation)
        
        # Monitoring and detection recommendations
        if kev_analysis:
            recommendations.append(
                "Implement enhanced monitoring and detection for systems with known exploited vulnerabilities"
            )
            
            recommendations.append(
                "Consider threat hunting activities focused on the specific attack patterns for these CWEs"
            )
        
        # Patch management recommendations
        total_cves = sum(data["cve_count"] for data in kev_analysis.values())
        if total_cves > 0:
            recommendations.append(
                f"Review patch management processes - {total_cves} CVEs with active exploits detected"
            )
        
        # Repository security recommendations
        all_repos = set()
        for data in kev_analysis.values():
            all_repos.update(data["top_repositories"].keys())
        
        if len(all_repos) > 1:
            recommendations.append(
                f"Implement emergency response procedures across {len(all_repos)} repositories "
                f"with exploitable vulnerabilities"
            )
        
        # Security team notifications
        if kev_analysis:
            recommendations.append(
                "Notify security incident response team of potential exposure to actively exploited vulnerabilities"
            )
        
        return recommendations