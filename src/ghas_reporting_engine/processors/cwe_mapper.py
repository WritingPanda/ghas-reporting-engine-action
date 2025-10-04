"""
CWE mapping functionality for compliance frameworks.

This module provides functionality to map Common Weakness Enumeration (CWE)
identifiers from GitHub Advanced Security alerts to compliance frameworks.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any

from ..utils.logger import get_logger


logger = get_logger("cwe_mapper")


class CWEMapper:
    """Maps CWEs to compliance frameworks."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the CWE mapper."""
        if data_dir is None:
            # Default to the data directory relative to this file
            current_dir = Path(__file__).parent.parent.parent.parent
            data_dir = current_dir / "data" / "cwe_mappings"
        
        self.data_dir = Path(data_dir)
        self._frameworks = {}
        self._load_frameworks()
    
    def _load_frameworks(self) -> None:
        """Load all framework mapping files."""
        framework_files = {
            "owasp": "owasp_top10.json",
            "sans": "sans_top25.json", 
            "mitre": "mitre_kev.json",
        }
        
        for framework_name, filename in framework_files.items():
            filepath = self.data_dir / filename
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    self._frameworks[framework_name] = json.load(f)
                logger.debug(f"Loaded {framework_name} framework mappings from {filepath}")
            except FileNotFoundError:
                logger.warning(f"Framework file not found: {filepath}")
                self._frameworks[framework_name] = {}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON in {filepath}: {e}")
                self._frameworks[framework_name] = {}
    
    def get_owasp_mappings(self, cwes: List[str]) -> Dict[str, List[str]]:
        """Map CWEs to OWASP Top 10 categories."""
        mappings = {}
        owasp_data = self._frameworks.get("owasp", {})
        categories = owasp_data.get("categories", {})
        
        for category_id, category_data in categories.items():
            category_name = category_data.get("name", category_id)
            category_cwes = set(category_data.get("cwes", []))
            
            # Find matching CWEs
            matching_cwes = [cwe for cwe in cwes if cwe in category_cwes]
            if matching_cwes:
                mappings[category_name] = matching_cwes
        
        return mappings
    
    def get_sans_mappings(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Map CWEs to SANS Top 25 rankings."""
        mappings = {}
        sans_data = self._frameworks.get("sans", {})
        rankings = sans_data.get("rankings", [])
        
        # Create a lookup dict for SANS rankings
        sans_lookup = {item["cwe"]: item for item in rankings}
        
        for cwe in cwes:
            if cwe in sans_lookup:
                sans_item = sans_lookup[cwe]
                mappings[cwe] = {
                    "rank": sans_item["rank"],
                    "name": sans_item["name"],
                    "url": sans_item.get("url", ""),
                }
        
        return mappings
    
    def get_mitre_kev_mappings(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Map CWEs to MITRE Known Exploited Vulnerabilities."""
        mappings = {}
        mitre_data = self._frameworks.get("mitre", {})
        kev_list = mitre_data.get("top_10_kev", [])
        
        # Create a lookup dict for MITRE KEV
        kev_lookup = {item["cwe"]: item for item in kev_list}
        
        for cwe in cwes:
            if cwe in kev_lookup:
                kev_item = kev_lookup[cwe]
                mappings[cwe] = {
                    "rank": kev_item["rank"],
                    "name": kev_item["name"],
                    "cve_count": kev_item["cve_count"],
                }
        
        return mappings
    
    def get_all_mappings(self, cwes: List[str]) -> Dict[str, Any]:
        """Get mappings for all frameworks."""
        return {
            "owasp": self.get_owasp_mappings(cwes),
            "sans": self.get_sans_mappings(cwes),
            "mitre_kev": self.get_mitre_kev_mappings(cwes),
        }
    
    def get_unmapped_cwes(self, cwes: List[str]) -> List[str]:
        """Get CWEs that don't map to any framework."""
        all_mapped_cwes = set()
        
        # Collect all CWEs from all frameworks
        owasp_data = self._frameworks.get("owasp", {})
        for category_data in owasp_data.get("categories", {}).values():
            all_mapped_cwes.update(category_data.get("cwes", []))
        
        sans_data = self._frameworks.get("sans", {})
        for item in sans_data.get("rankings", []):
            all_mapped_cwes.add(item["cwe"])
        
        mitre_data = self._frameworks.get("mitre", {})
        for item in mitre_data.get("top_10_kev", []):
            all_mapped_cwes.add(item["cwe"])
        
        # Find unmapped CWEs
        unmapped = [cwe for cwe in cwes if cwe not in all_mapped_cwes]
        return unmapped
    
    def get_framework_summary(self, framework: str) -> Dict[str, Any]:
        """Get summary information about a framework."""
        framework_data = self._frameworks.get(framework, {})
        
        if framework == "owasp":
            categories = framework_data.get("categories", {})
            return {
                "name": framework_data.get("framework", "OWASP Top 10"),
                "version": framework_data.get("version", "2021"),
                "category_count": len(categories),
                "total_cwes": sum(len(cat.get("cwes", [])) for cat in categories.values()),
            }
        elif framework == "sans":
            rankings = framework_data.get("rankings", [])
            return {
                "name": framework_data.get("framework", "SANS Top 25"),
                "version": framework_data.get("version", "2023"),
                "ranking_count": len(rankings),
                "total_cwes": len(rankings),
            }
        elif framework == "mitre":
            kev_list = framework_data.get("top_10_kev", [])
            return {
                "name": framework_data.get("framework", "MITRE KEV"),
                "version": framework_data.get("version", "2024"),
                "kev_count": len(kev_list),
                "total_cwes": len(kev_list),
            }
        else:
            return {}