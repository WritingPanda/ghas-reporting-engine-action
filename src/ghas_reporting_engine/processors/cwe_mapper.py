"""
CWE to framework mapping engine.

This module handles mapping CWEs to compliance frameworks including
OWASP Top 10, SANS Top 25, and MITRE KEV.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Set

from ..frameworks.mitre_kev import MITREKEVProcessor
from ..frameworks.owasp_top10 import OWASPTop10Processor
from ..frameworks.sans_top25 import SANSTop25Processor
from ..utils.logger import get_logger

logger = get_logger("cwe_mapper")


class CWEMapper:
    """Maps CWEs to compliance frameworks."""

    def __init__(self):
        """Initialize the CWE mapper with framework processors."""
        # Initialize framework processors
        self.owasp_processor = OWASPTop10Processor()
        self.sans_processor = SANSTop25Processor()
        self.mitre_processor = MITREKEVProcessor()

        logger.info("CWE Mapper initialized successfully")

    def get_owasp_mappings(self, cwes: List[str]) -> Dict[str, List[str]]:
        """Get OWASP Top 10 mappings for given CWEs."""
        return self.owasp_processor.map_cwes(cwes)

    def get_sans_mappings(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get SANS Top 25 mappings for given CWEs."""
        return self.sans_processor.map_cwes(cwes)

    def get_mitre_kev_mappings(self, cwes: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get MITRE KEV mappings for given CWEs."""
        return self.mitre_processor.map_cwes(cwes)

    def get_framework_summary(self, framework: str) -> Dict[str, Any]:
        """Get metadata summary for a framework."""
        if framework == "owasp":
            return self.owasp_processor.get_summary()
        elif framework == "sans":
            return self.sans_processor.get_summary()
        elif framework == "mitre":
            return self.mitre_processor.get_summary()
        else:
            logger.warning(f"Unknown framework: {framework}")
            return {}

    def get_unmapped_cwes(self, cwes: List[str]) -> List[str]:
        """Find CWEs that don't map to any framework."""
        unmapped = set(cwes)

        # Remove CWEs that map to any framework
        owasp_mapped = self._get_all_mapped_cwes(self.get_owasp_mappings(cwes))
        sans_mapped = set(self.get_sans_mappings(cwes).keys())
        mitre_mapped = set(self.get_mitre_kev_mappings(cwes).keys())

        unmapped -= owasp_mapped
        unmapped -= sans_mapped
        unmapped -= mitre_mapped

        return sorted(list(unmapped))

    def _get_all_mapped_cwes(self, mappings: Dict[str, List[str]]) -> Set[str]:
        """Extract all CWEs from category mappings."""
        all_cwes = set()
        for cwes in mappings.values():
            all_cwes.update(cwes)
        return all_cwes
