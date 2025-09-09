import { CodeQLAlert } from '../types';


/**
 * Utility class for extracting CWE information from CodeQL alerts
 */
export class CWEExtractor {
  /**
   * Extract CWE IDs from a CodeQL alert
   */
  static extractCWEs(alert: CodeQLAlert): string[] {
    const cwes: string[] = [];

    // Check rule tags for CWE references
    if (alert.rule.tags) {
      for (const tag of alert.rule.tags) {
        const cweMatch = tag.match(/external\/cwe\/cwe-(\d+)/i);
        if (cweMatch) {
          cwes.push(`CWE-${cweMatch[1]}`);
        }
      }
    }

    // Check rule description for CWE references
    if (alert.rule.description) {
      const cweMatches = alert.rule.description.match(/CWE-\d+/gi);
      if (cweMatches) {
        cwes.push(...cweMatches.map(cwe => cwe.toUpperCase()));
      }
    }

    // Check rule name for CWE references
    if (alert.rule.name) {
      const cweMatches = alert.rule.name.match(/CWE-\d+/gi);
      if (cweMatches) {
        cwes.push(...cweMatches.map(cwe => cwe.toUpperCase()));
      }
    }

    // Check classifications for CWE references
    if (alert.most_recent_instance.classifications) {
      for (const classification of alert.most_recent_instance.classifications) {
        const cweMatch = classification.match(/CWE-\d+/i);
        if (cweMatch) {
          cwes.push(cweMatch[0].toUpperCase());
        }
      }
    }

    // Remove duplicates and return
    return [...new Set(cwes)];
  }

  /**
   * Check if an alert has any CWE mapping
   */
  static hasCWEMapping(alert: CodeQLAlert): boolean {
    return this.extractCWEs(alert).length > 0;
  }

  /**
   * Get a formatted CWE list as a string
   */
  static formatCWEs(cwes: string[]): string {
    return cwes.join(', ');
  }

  /**
   * Extract CWE number from CWE ID (e.g., "CWE-787" -> "787")
   */
  static extractCWENumber(cwe: string): string {
    const match = cwe.match(/CWE-(\d+)/i);
    return match ? match[1] : '';
  }
}
