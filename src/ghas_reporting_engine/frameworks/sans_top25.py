"""
SANS Top 25 specific processing and analysis.

This module provides SANS Top 25 Most Dangerous Software Errors
specific processing and insights for GitHub Advanced Security alerts.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict

from ..api.models import Alert
from ..processors.cwe_mapper import CWEMapper
from ..utils.logger import get_logger


logger = get_logger("sans_processor")


class SANSTop25Processor:
    """Processor for SANS Top 25 analysis."""
    
    def __init__(self):
        """Initialize the SANS processor."""
        self.cwe_mapper = CWEMapper()
    
    def process(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Process alerts for SANS Top 25 analysis."""
        logger.info(f"Processing {len(alerts)} alerts for SANS Top 25 analysis")
        
        # Extract all CWEs
        all_cwes = set()
        for alert in alerts:
            all_cwes.update(alert.cwes)
        
        # Get SANS mappings
        sans_mappings = self.cwe_mapper.get_sans_mappings(list(all_cwes))
        
        # Analyze alerts by SANS ranking
        ranking_analysis = self._analyze_by_ranking(alerts, sans_mappings)
        
        # Generate insights
        insights = self._generate_insights(ranking_analysis, alerts)
        
        # Calculate priority scores
        priority_scores = self._calculate_priority_scores(ranking_analysis)
        
        return {
            "framework": "SANS Top 25 Most Dangerous Software Errors",
            "total_alerts": len(alerts),
            "mapped_alerts": sum(rank["alert_count"] for rank in ranking_analysis.values()),
            "rankings": ranking_analysis,
            "insights": insights,
            "priority_scores": priority_scores,
            "recommendations": self._generate_recommendations(ranking_analysis),
        }
    
    def _analyze_by_ranking(self, alerts: List[Alert], mappings: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze alerts by SANS ranking."""
        ranking_analysis = {}
        
        # Group alerts by CWE that maps to SANS
        for alert in alerts:
            for cwe in alert.cwes:
                if cwe in mappings:
                    sans_info = mappings[cwe]
                    rank = sans_info["rank"]
                    name = sans_info["name"]
                    
                    if cwe not in ranking_analysis:
                        ranking_analysis[cwe] = {
                            "cwe": cwe,
                            "rank": rank,
                            "name": name,
                            "url": sans_info.get("url", ""),
                            "alert_count": 0,
                            "alerts": [],
                            "severity_distribution": defaultdict(int),
                            "state_distribution": defaultdict(int),
                            "repository_distribution": defaultdict(int),
                            "rule_distribution": defaultdict(int),
                        }
                    
                    analysis = ranking_analysis[cwe]
                    analysis["alert_count"] += 1
                    analysis["alerts"].append(alert)
                    analysis["severity_distribution"][alert.severity_level] += 1
                    analysis["state_distribution"][alert.state] += 1
                    analysis["repository_distribution"][alert.repository.full_name] += 1
                    analysis["rule_distribution"][alert.rule.id] += 1
        
        # Convert defaultdicts to regular dicts and remove alert objects for JSON serialization
        for cwe, analysis in ranking_analysis.items():
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
        
        return ranking_analysis
    
    def _generate_insights(self, ranking_analysis: Dict[str, Any], alerts: List[Alert]) -> List[str]:
        """Generate insights about SANS findings."""
        insights = []
        
        if not ranking_analysis:
            insights.append("No alerts mapped to SANS Top 25 CWEs.")
            return insights
        
        # Coverage analysis
        total_sans_cwes = 25  # SANS Top 25
        covered_cwes = len(ranking_analysis)
        coverage_percent = (covered_cwes / total_sans_cwes) * 100
        insights.append(
            f"SANS Top 25 coverage: {covered_cwes}/{total_sans_cwes} CWEs ({coverage_percent:.1f}%)"
        )
        
        # Most problematic CWE by ranking
        if ranking_analysis:
            top_ranked_cwe = min(ranking_analysis.items(), key=lambda x: x[1]["rank"])
            insights.append(
                f"Highest ranked SANS CWE found: {top_ranked_cwe[0]} (Rank #{top_ranked_cwe[1]['rank']}) "
                f"with {top_ranked_cwe[1]['alert_count']} alerts"
            )
        
        # Most frequent CWE
        most_frequent = max(ranking_analysis.items(), key=lambda x: x[1]["alert_count"])
        insights.append(
            f"Most frequent SANS CWE: {most_frequent[0]} with {most_frequent[1]['alert_count']} alerts "
            f"(Rank #{most_frequent[1]['rank']})"
        )
        
        # Top 5 analysis
        top_5_cwes = [cwe for cwe, data in ranking_analysis.items() if data["rank"] <= 5]
        if top_5_cwes:
            top_5_alerts = sum(ranking_analysis[cwe]["alert_count"] for cwe in top_5_cwes)
            total_mapped = sum(data["alert_count"] for data in ranking_analysis.values())
            top_5_percent = (top_5_alerts / total_mapped) * 100 if total_mapped > 0 else 0
            insights.append(
                f"SANS Top 5 CWEs account for {top_5_alerts} alerts ({top_5_percent:.1f}% of mapped alerts)"
            )
        
        # Critical/High severity in top rankings
        critical_high_in_top_10 = 0
        for cwe, data in ranking_analysis.items():
            if data["rank"] <= 10:
                critical_high_in_top_10 += data["severity_distribution"].get("critical", 0)
                critical_high_in_top_10 += data["severity_distribution"].get("high", 0)
        
        if critical_high_in_top_10 > 0:
            insights.append(
                f"{critical_high_in_top_10} critical/high severity alerts found in SANS Top 10 CWEs"
            )
        
        return insights
    
    def _calculate_priority_scores(self, ranking_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Calculate priority scores for each SANS CWE."""
        priority_scores = {}
        
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
        
        for cwe, data in ranking_analysis.items():
            # Base score from SANS ranking (higher rank = lower score)
            rank_score = (26 - data["rank"]) / 25.0  # Normalize to 0-1, rank 1 = 1.0, rank 25 = 0.04
            
            # Severity score
            severity_score = 0.0
            total_alerts = data["alert_count"]
            
            if total_alerts > 0:
                for severity, count in data["severity_distribution"].items():
                    severity_weight = severity_weights.get(severity, 1.0)
                    severity_score += (count / total_alerts) * severity_weight
                
                severity_score /= 4.0  # Normalize to 0-1
            
            # State score (how many are still open)
            state_score = 0.0
            if total_alerts > 0:
                for state, count in data["state_distribution"].items():
                    state_weight = state_weights.get(state, 1.0)
                    state_score += (count / total_alerts) * state_weight
            
            # Volume score (logarithmic scale for alert count)
            import math
            volume_score = min(math.log10(total_alerts + 1) / 3.0, 1.0)  # Cap at 1000 alerts
            
            # Combined score (weighted average)
            combined_score = (
                rank_score * 0.4 +      # 40% weight on SANS ranking
                severity_score * 0.3 +   # 30% weight on severity
                state_score * 0.2 +      # 20% weight on state
                volume_score * 0.1       # 10% weight on volume
            )
            
            priority_scores[cwe] = round(combined_score * 10.0, 2)  # Scale to 0-10
        
        return priority_scores
    
    def _generate_recommendations(self, ranking_analysis: Dict[str, Any]) -> List[str]:
        """Generate SANS-specific recommendations."""
        recommendations = []
        
        if not ranking_analysis:
            recommendations.append("No SANS Top 25 issues identified in the current analysis.")
            return recommendations
        
        # Sort by SANS ranking (most dangerous first)
        sorted_by_rank = sorted(ranking_analysis.items(), key=lambda x: x[1]["rank"])
        
        # Recommendations for top ranked CWEs found
        for i, (cwe, data) in enumerate(sorted_by_rank[:3]):
            critical_count = data["severity_distribution"].get("critical", 0)
            high_count = data["severity_distribution"].get("high", 0)
            
            recommendations.append(
                f"Priority {i+1}: Address {cwe} (SANS Rank #{data['rank']}) - "
                f"{data['alert_count']} alerts found"
            )
            
            if critical_count > 0 or high_count > 0:
                recommendations[-1] += f" ({critical_count + high_count} critical/high severity)"
        
        # Top 5 specific recommendation
        top_5_cwes = [cwe for cwe, data in ranking_analysis.items() if data["rank"] <= 5]
        if top_5_cwes:
            recommendations.append(
                f"Focus immediate attention on SANS Top 5 CWEs found: {', '.join(top_5_cwes)}"
            )
        
        # Repository recommendations
        all_repos = set()
        for data in ranking_analysis.values():
            all_repos.update(data["top_repositories"].keys())
        
        if len(all_repos) > 1:
            recommendations.append(
                f"Implement consistent secure coding practices across {len(all_repos)} repositories"
            )
        
        # Training recommendations
        common_categories = self._get_common_weakness_categories(ranking_analysis)
        if common_categories:
            recommendations.append(
                f"Consider targeted developer training on: {', '.join(common_categories)}"
            )
        
        return recommendations
    
    def _get_common_weakness_categories(self, ranking_analysis: Dict[str, Any]) -> List[str]:
        """Identify common categories of weaknesses for training recommendations."""
        categories = []
        
        # Check for common patterns in found CWEs
        found_cwes = list(ranking_analysis.keys())
        
        # Injection-related CWEs
        injection_cwes = ["CWE-79", "CWE-89", "CWE-78", "CWE-77", "CWE-94"]
        if any(cwe in found_cwes for cwe in injection_cwes):
            categories.append("Input validation and injection prevention")
        
        # Memory safety CWEs
        memory_cwes = ["CWE-787", "CWE-416", "CWE-125", "CWE-119"]
        if any(cwe in found_cwes for cwe in memory_cwes):
            categories.append("Memory safety and buffer management")
        
        # Authentication/Authorization CWEs
        auth_cwes = ["CWE-862", "CWE-287", "CWE-306", "CWE-269", "CWE-863", "CWE-276"]
        if any(cwe in found_cwes for cwe in auth_cwes):
            categories.append("Authentication and authorization controls")
        
        # Input validation CWEs
        validation_cwes = ["CWE-20", "CWE-22", "CWE-352", "CWE-434"]
        if any(cwe in found_cwes for cwe in validation_cwes):
            categories.append("Input validation and sanitization")
        
        return categories[:3]  # Return top 3 categories