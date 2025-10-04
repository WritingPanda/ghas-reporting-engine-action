"""
CSV report generator for GHAS reports.

This module generates CSV reports from GHAS alert analysis for spreadsheet analysis.
"""

import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple

from .base_reporter import BaseReporter
from ..processors.data_analyzer import AnalysisResult
from ..utils.logger import get_logger


logger = get_logger("csv_reporter")


class CSVReporter(BaseReporter):
    """CSV report generator."""
    
    def _get_format_name(self) -> str:
        """Get the format name for this reporter."""
        return "csv"
    
    def _generate_single_report(
        self, 
        analysis_result: AnalysisResult, 
        report_type: str, 
        output_path: Path
    ) -> None:
        """Generate a single CSV report for the specified type."""
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate different CSV structures based on report type
        if report_type == "owasp":
            self._generate_owasp_csv(analysis_result, output_path)
        elif report_type == "sans":
            self._generate_sans_csv(analysis_result, output_path)
        elif report_type == "mitre":
            self._generate_mitre_csv(analysis_result, output_path)
    
    def _generate_owasp_csv(self, analysis_result: AnalysisResult, output_path: Path) -> None:
        """Generate OWASP Top 10 CSV report."""
        owasp_data = analysis_result.framework_mappings.get("owasp", {})
        category_counts = owasp_data.get("category_counts", {})
        mappings = owasp_data.get("mappings", {})
        
        rows = []
        
        # Header row
        headers = [
            "OWASP_Category",
            "Alert_Count",
            "Mapped_CWEs",
            "CWE_Count",
            "Percentage_of_Total",
            "Risk_Level",
        ]
        
        total_mapped_alerts = sum(category_counts.values()) if category_counts else 0
        
        for category, alert_count in category_counts.items():
            mapped_cwes = mappings.get(category, [])
            percentage = (alert_count / total_mapped_alerts) * 100 if total_mapped_alerts > 0 else 0
            
            # Simple risk level calculation
            if alert_count >= 50:
                risk_level = "High"
            elif alert_count >= 20:
                risk_level = "Medium"
            elif alert_count >= 5:
                risk_level = "Low"
            else:
                risk_level = "Minimal"
            
            rows.append([
                category,
                alert_count,
                "; ".join(mapped_cwes),
                len(mapped_cwes),
                f"{percentage:.1f}%",
                risk_level,
            ])
        
        # Sort by alert count descending
        rows.sort(key=lambda x: x[1], reverse=True)
        
        # Write CSV
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        logger.info(f"Generated OWASP CSV report with {len(rows)} categories")
    
    def _generate_sans_csv(self, analysis_result: AnalysisResult, output_path: Path) -> None:
        """Generate SANS Top 25 CSV report."""
        sans_data = analysis_result.framework_mappings.get("sans", {})
        cwe_counts = sans_data.get("cwe_counts", {})
        mappings = sans_data.get("mappings", {})
        
        rows = []
        
        # Header row
        headers = [
            "CWE_ID",
            "SANS_Rank",
            "CWE_Name",
            "Alert_Count",
            "MITRE_URL",
            "Priority_Level",
        ]
        
        for cwe, alert_count in cwe_counts.items():
            mapping_info = mappings.get(cwe, {})
            rank = mapping_info.get("rank", 999)
            name = mapping_info.get("name", "Unknown")
            url = mapping_info.get("url", "")
            
            # Priority level based on SANS ranking and alert count
            if rank <= 5 and alert_count >= 10:
                priority = "Critical"
            elif rank <= 10 and alert_count >= 5:
                priority = "High"
            elif rank <= 15:
                priority = "Medium"
            else:
                priority = "Low"
            
            rows.append([
                cwe,
                rank,
                name,
                alert_count,
                url,
                priority,
            ])
        
        # Sort by SANS rank
        rows.sort(key=lambda x: x[1])
        
        # Write CSV
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        logger.info(f"Generated SANS CSV report with {len(rows)} CWEs")
    
    def _generate_mitre_csv(self, analysis_result: AnalysisResult, output_path: Path) -> None:
        """Generate MITRE KEV CSV report."""
        mitre_data = analysis_result.framework_mappings.get("mitre", {})
        cwe_counts = mitre_data.get("cwe_counts", {})
        mappings = mitre_data.get("mappings", {})
        
        rows = []
        
        # Header row
        headers = [
            "CWE_ID",
            "KEV_Rank",
            "CWE_Name",
            "Alert_Count",
            "Known_Exploited_CVEs",
            "Criticality_Level",
            "Immediate_Action_Required",
        ]
        
        for cwe, alert_count in cwe_counts.items():
            mapping_info = mappings.get(cwe, {})
            rank = mapping_info.get("rank", 999)
            name = mapping_info.get("name", "Unknown")
            cve_count = mapping_info.get("cve_count", 0)
            
            # Criticality level based on KEV ranking and CVE count
            if rank <= 3 and cve_count >= 5:
                criticality = "Critical"
                immediate_action = "YES"
            elif rank <= 5 and cve_count >= 3:
                criticality = "High"
                immediate_action = "YES"
            elif rank <= 10:
                criticality = "Medium"
                immediate_action = "RECOMMENDED"
            else:
                criticality = "Low"
                immediate_action = "NO"
            
            rows.append([
                cwe,
                rank,
                name,
                alert_count,
                cve_count,
                criticality,
                immediate_action,
            ])
        
        # Sort by KEV rank
        rows.sort(key=lambda x: x[1])
        
        # Write CSV
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        logger.info(f"Generated MITRE KEV CSV report with {len(rows)} CWEs")