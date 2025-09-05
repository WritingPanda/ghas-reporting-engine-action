import { CodeQLAlert, FrameworkMapping } from '../types';
import { CWEExtractor } from '../utils/CWEExtractor';
import { OWASP_TOP_10_MAPPINGS, SANS_TOP_25_MAPPINGS, MITRE_KEV_MAPPINGS } from './mappings';

/**
 * Base class for framework analyzers
 */
export abstract class FrameworkAnalyzer {
  abstract analyzeAlerts(alerts: CodeQLAlert[]): FrameworkMapping[];
  abstract getFrameworkName(): string;
}

/**
 * OWASP Top 10 analyzer
 */
export class OWASPAnalyzer extends FrameworkAnalyzer {
  getFrameworkName(): string {
    return 'OWASP Top 10 2021';
  }

  analyzeAlerts(alerts: CodeQLAlert[]): FrameworkMapping[] {
    const mappings: FrameworkMapping[] = [];

    for (const [category, info] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
      const categoryAlerts = alerts.filter(alert => {
        const alertCWEs = CWEExtractor.extractCWEs(alert);
        return alertCWEs.some(cwe => info.cwes.some(cweInfo => cweInfo.cwe === cwe));
      });

      mappings.push({
        framework: 'OWASP',
        category: `${category} - ${info.name}`,
        cwes: info.cwes.map(cweInfo => cweInfo.cwe),
        alertCount: categoryAlerts.length,
        alerts: categoryAlerts
      });
    }

    return mappings.sort((a, b) => b.alertCount - a.alertCount);
  }
}

/**
 * SANS Top 25 analyzer
 */
export class SANSAnalyzer extends FrameworkAnalyzer {
  getFrameworkName(): string {
    return 'SANS Top 25';
  }

  analyzeAlerts(alerts: CodeQLAlert[]): FrameworkMapping[] {
    const mappings: FrameworkMapping[] = [];

    for (const [rank, info] of Object.entries(SANS_TOP_25_MAPPINGS)) {
      const categoryAlerts = alerts.filter(alert => {
        const alertCWEs = CWEExtractor.extractCWEs(alert);
        return alertCWEs.includes(info.cwe);
      });

      mappings.push({
        framework: 'SANS',
        category: `#${rank} - ${info.name}`,
        rank: parseInt(rank),
        cwes: [info.cwe],
        alertCount: categoryAlerts.length,
        alerts: categoryAlerts
      });
    }

    return mappings.sort((a, b) => (a.rank || 0) - (b.rank || 0));
  }
}

/**
 * MITRE KEV analyzer
 */
export class MITREKEVAnalyzer extends FrameworkAnalyzer {
  getFrameworkName(): string {
    return 'MITRE Top 10 KEV';
  }

  analyzeAlerts(alerts: CodeQLAlert[]): FrameworkMapping[] {
    const mappings: FrameworkMapping[] = [];

    for (const [rank, info] of Object.entries(MITRE_KEV_MAPPINGS)) {
      const categoryAlerts = alerts.filter(alert => {
        const alertCWEs = CWEExtractor.extractCWEs(alert);
        return alertCWEs.includes(info.cwe);
      });

      mappings.push({
        framework: 'MITRE KEV',
        category: `#${rank} - ${info.name} (Score: ${info.score})`,
        rank: parseInt(rank),
        cwes: [info.cwe],
        alertCount: categoryAlerts.length,
        alerts: categoryAlerts
      });
    }

    return mappings.sort((a, b) => (a.rank || 0) - (b.rank || 0));
  }
}

/**
 * Factory for creating framework analyzers
 */
export class FrameworkAnalyzerFactory {
  static createAnalyzer(framework: string): FrameworkAnalyzer {
    switch (framework.toLowerCase()) {
      case 'owasp':
        return new OWASPAnalyzer();
      case 'sans':
        return new SANSAnalyzer();
      case 'kev':
      case 'mitre':
        return new MITREKEVAnalyzer();
      default:
        throw new Error(`Unsupported framework: ${framework}`);
    }
  }

  static getSupportedFrameworks(): string[] {
    return ['owasp', 'sans', 'kev'];
  }
}
