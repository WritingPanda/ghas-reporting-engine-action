/**
 * Utility functions for extracting and processing CWE information from CodeQL alerts
 */

import { CWEInfo } from '../types';

/**
 * Regular expression to match CWE tags in the format "external/cwe/cwe-XXX"
 */
const CWE_TAG_REGEX = /external\/cwe\/cwe-(\d+)/i;

/**
 * Extract CWE information from alert rule tags
 * @param tags Array of tags from the alert rule
 * @returns Array of CWE information objects
 */
export function extractCWEsFromTags(tags: string[]): CWEInfo[] {
  const cwes: CWEInfo[] = [];

  for (const tag of tags) {
    const match = tag.match(CWE_TAG_REGEX);
    if (match && match[1]) {
      const cweNumber = parseInt(match[1], 10);
      cwes.push({
        id: `CWE-${cweNumber}`,
        number: cweNumber,
      });
    }
  }

  return cwes;
}

/**
 * Extract unique CWE numbers from a collection of tags
 * @param tagCollections Array of tag arrays from multiple alerts
 * @returns Array of unique CWE numbers
 */
export function extractUniqueCWEs(tagCollections: string[][]): number[] {
  const cweSet = new Set<number>();

  for (const tags of tagCollections) {
    const cwes = extractCWEsFromTags(tags);
    for (const cwe of cwes) {
      cweSet.add(cwe.number);
    }
  }

  return Array.from(cweSet).sort((a, b) => a - b);
}

/**
 * Check if an alert has any CWE tags
 * @param tags Array of tags from the alert rule
 * @returns True if the alert has CWE tags
 */
export function hasCWETags(tags: string[]): boolean {
  return tags.some(tag => CWE_TAG_REGEX.test(tag));
}

/**
 * Group CWEs by their severity level based on CVSS scoring
 * Note: This is a simplified mapping. In practice, you might want to
 * integrate with a CWE database for more accurate severity mapping.
 * @param cweNumbers Array of CWE numbers
 * @returns Object with CWEs grouped by severity
 */
export function groupCWEsBySeverity(cweNumbers: number[]): {
  critical: number[];
  high: number[];
  medium: number[];
  low: number[];
} {
  // This is a simplified mapping. In a real implementation,
  // you would integrate with CWE database or CVSS scores
  const criticalCWEs = [89, 79, 200, 287, 732]; // SQL Injection, XSS, Info Exposure, Auth Issues, etc.
  const highCWEs = [22, 352, 434, 78, 77]; // Path Traversal, CSRF, Download of Code, OS Command Injection, etc.
  const mediumCWEs = [476, 190, 125, 129]; // NULL Pointer, Integer Overflow, etc.

  return {
    critical: cweNumbers.filter(cwe => criticalCWEs.includes(cwe)),
    high: cweNumbers.filter(cwe => highCWEs.includes(cwe)),
    medium: cweNumbers.filter(cwe => mediumCWEs.includes(cwe)),
    low: cweNumbers.filter(cwe =>
      !criticalCWEs.includes(cwe) &&
      !highCWEs.includes(cwe) &&
      !mediumCWEs.includes(cwe)
    ),
  };
}

/**
 * Validate that a CWE number is valid (positive integer)
 * @param cweNumber The CWE number to validate
 * @returns True if the CWE number is valid
 */
export function isValidCWE(cweNumber: number): boolean {
  return Number.isInteger(cweNumber) && cweNumber > 0;
}

/**
 * Format CWE information for display
 * @param cwe CWE information object
 * @returns Formatted string representation
 */
export function formatCWE(cwe: CWEInfo): string {
  return `${cwe.id}${cwe.name ? ` - ${cwe.name}` : ''}`;
}