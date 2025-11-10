"""
SANS Top 25 framework processor.

Maps CWEs to SANS Top 25 Most Dangerous Software Weaknesses.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from ..utils.logger import get_logger

logger = get_logger("sans_processor")


class SANSTop25Processor:
    """Process and map CWEs to SANS Top 25."""

    def __init__(self):
        """Initialize the SANS processor and load mappings."""
        self.mapping_file = Path(__file__).parent.parent.parent / "data" / "cwe_mappings" / "sans_top25.json"
        self.mappings = self._load_mappings()
        logger.info(f"Loaded SANS Top 25 mappings: {len(self.mappings.get('rankings', {}))} CWEs")

    def _load_mappings(self) -> Dict[str, Any]:
        """Load SANS mappings from JSON file."""
        try:
            with open(self.mapping_file, "r") as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            logger.warning(f"SANS mapping file not found: {self.mapping_file}")
            return {"framework": "SANS Top 25", "version": "2023", "rankings": {}}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SANS mappings: {e}")
            return {"framework": "SANS Top 25", "version": "2023", "rankings": {}}

    def map_cwes(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Map CWEs to SANS rankings."""
        cwe_mappings: Dict[str, Dict[str, Any]] = {}

        rankings = self.mappings.get("rankings", {})

        for cwe in cwes:
            # Normalize CWE format
            normalized_cwe = cwe.upper() if cwe.startswith("CWE-") else f"CWE-{cwe}"

            if normalized_cwe in rankings:
                cwe_mappings[normalized_cwe] = rankings[normalized_cwe]

        return cwe_mappings

    def get_summary(self) -> Dict[str, Any]:
        """Get SANS framework summary."""
        rankings = self.mappings.get("rankings", {})

        return {
            "framework": self.mappings.get("framework", "SANS Top 25"),
            "version": self.mappings.get("version", "2023"),
            "description": self.mappings.get("description", "CWE Top 25 Most Dangerous Software Weaknesses"),
            "total_cwes": len(rankings),
            "top_10_cwes": [
                {
                    "cwe": cwe_id,
                    "rank": cwe_data.get("rank"),
                    "name": cwe_data.get("name", ""),
                    "score": cwe_data.get("score", 0),
                }
                for cwe_id, cwe_data in sorted(
                    rankings.items(), key=lambda x: x[1].get("rank", 999)
                )[:10]
            ],
        }

    def get_cwe_details(self, cwe_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific CWE."""
        rankings = self.mappings.get("rankings", {})
        normalized_cwe = cwe_id.upper() if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
        return rankings.get(normalized_cwe, {})

    def get_mitigation_strategies(self, cwe_id: str) -> List[str]:
        """Get mitigation strategies for a specific CWE."""
        cwe_data = self.get_cwe_details(cwe_id)
        return cwe_data.get("mitigation", [])
