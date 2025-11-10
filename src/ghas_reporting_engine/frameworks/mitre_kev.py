"""
MITRE Top 10 KEV framework processor.

Maps CWEs to MITRE's Known Exploited Vulnerabilities catalog.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from ..utils.logger import get_logger

logger = get_logger("mitre_processor")


class MITREKEVProcessor:
    """Process and map CWEs to MITRE KEV."""

    def __init__(self):
        """Initialize the MITRE processor and load mappings."""
        self.mapping_file = Path(__file__).parent.parent.parent / "data" / "cwe_mappings" / "mitre_kev.json"
        self.mappings = self._load_mappings()
        logger.info(f"Loaded MITRE KEV mappings: {len(self.mappings.get('top_10_kev', {}))} CWEs")

    def _load_mappings(self) -> Dict[str, Any]:
        """Load MITRE KEV mappings from JSON file."""
        try:
            with open(self.mapping_file, "r") as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            logger.warning(f"MITRE mapping file not found: {self.mapping_file}")
            return {"framework": "MITRE Top 10 KEV", "version": "1.0", "top_10_kev": {}}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse MITRE mappings: {e}")
            return {"framework": "MITRE Top 10 KEV", "version": "1.0", "top_10_kev": {}}

    def map_cwes(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Map CWEs to MITRE KEV catalog."""
        cwe_mappings: Dict[str, Dict[str, Any]] = {}

        kev_cwes = self.mappings.get("top_10_kev", {})

        for cwe in cwes:
            # Normalize CWE format
            normalized_cwe = cwe.upper() if cwe.startswith("CWE-") else f"CWE-{cwe}"

            if normalized_cwe in kev_cwes:
                cwe_mappings[normalized_cwe] = kev_cwes[normalized_cwe]

        return cwe_mappings

    def get_summary(self) -> Dict[str, Any]:
        """Get MITRE KEV framework summary."""
        kev_cwes = self.mappings.get("top_10_kev", {})

        return {
            "framework": self.mappings.get("framework", "MITRE Top 10 KEV"),
            "version": self.mappings.get("version", "1.0"),
            "description": self.mappings.get(
                "description", "MITRE Top 10 CWEs from Known Exploited Vulnerabilities Catalog"
            ),
            "total_cwes": len(kev_cwes),
            "top_10_cwes": [
                {
                    "cwe": cwe_id,
                    "rank": cwe_data.get("rank"),
                    "name": cwe_data.get("name", ""),
                    "vulnerability_count": cwe_data.get("vulnerability_count", 0),
                }
                for cwe_id, cwe_data in sorted(kev_cwes.items(), key=lambda x: x[1].get("rank", 999))
            ],
        }

    def get_cwe_details(self, cwe_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific CWE."""
        kev_cwes = self.mappings.get("top_10_kev", {})
        normalized_cwe = cwe_id.upper() if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
        return kev_cwes.get(normalized_cwe, {})

    def get_exploitation_info(self, cwe_id: str) -> Dict[str, Any]:
        """Get exploitation information for a specific CWE."""
        cwe_data = self.get_cwe_details(cwe_id)
        return {
            "vulnerability_count": cwe_data.get("vulnerability_count", 0),
            "exploitation_evidence": cwe_data.get("exploitation_evidence", "Unknown"),
            "priority": cwe_data.get("priority", "Review"),
        }
