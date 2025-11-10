"""
OWASP Top 10 2021 framework processor.

Maps CWEs to OWASP Top 10 categories and provides framework metadata.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from ..utils.logger import get_logger

logger = get_logger("owasp_processor")


class OWASPTop10Processor:
    """Process and map CWEs to OWASP Top 10 2021."""

    def __init__(self):
        """Initialize the OWASP processor and load mappings."""
        self.mapping_file = Path(__file__).parent.parent.parent / "data" / "cwe_mappings" / "owasp_top10.json"
        self.mappings = self._load_mappings()
        logger.info(f"Loaded OWASP Top 10 mappings: {len(self.mappings.get('categories', {}))} categories")

    def _load_mappings(self) -> Dict[str, Any]:
        """Load OWASP mappings from JSON file."""
        try:
            with open(self.mapping_file, "r") as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            logger.warning(f"OWASP mapping file not found: {self.mapping_file}")
            return {"framework": "OWASP Top 10 2021", "version": "1.0", "categories": {}}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OWASP mappings: {e}")
            return {"framework": "OWASP Top 10 2021", "version": "1.0", "categories": {}}

    def map_cwes(self, cwes: List[str]) -> Dict[str, List[str]]:
        """Map CWEs to OWASP categories."""
        category_mappings: Dict[str, List[str]] = {}

        categories = self.mappings.get("categories", {})

        for category_id, category_data in categories.items():
            mapped_cwes = []
            category_cwes = category_data.get("cwes", [])

            for cwe in cwes:
                # Normalize CWE format
                normalized_cwe = cwe.upper() if cwe.startswith("CWE-") else f"CWE-{cwe}"

                if normalized_cwe in category_cwes:
                    mapped_cwes.append(normalized_cwe)

            if mapped_cwes:
                category_name = category_data.get("name", category_id)
                category_mappings[f"{category_id}: {category_name}"] = mapped_cwes

        return category_mappings

    def get_summary(self) -> Dict[str, Any]:
        """Get OWASP framework summary."""
        categories = self.mappings.get("categories", {})

        return {
            "framework": self.mappings.get("framework", "OWASP Top 10 2021"),
            "version": self.mappings.get("version", "1.0"),
            "description": self.mappings.get("description", "OWASP Top 10 Web Application Security Risks"),
            "total_categories": len(categories),
            "categories": [
                {
                    "id": cat_id,
                    "name": cat_data.get("name", ""),
                    "description": cat_data.get("description", ""),
                    "cwe_count": len(cat_data.get("cwes", [])),
                }
                for cat_id, cat_data in categories.items()
            ],
        }

    def get_category_details(self, category_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific category."""
        categories = self.mappings.get("categories", {})
        return categories.get(category_id, {})

    def get_prevention_tips(self, category_id: str) -> List[str]:
        """Get prevention tips for a specific category."""
        category = self.get_category_details(category_id)
        return category.get("prevention", [])
