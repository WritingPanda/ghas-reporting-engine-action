import { GeneratedReport, FrameworkMapping, CodeQLAlert } from '../types';
import { CWEExtractor } from '../utils/CWEExtractor';

/**
 * Base class for report generators
 */
export abstract class ReportGenerator {
  abstract generateReport(
    framework: string,
    mappings: FrameworkMapping[],
    allAlerts: CodeQLAlert[],
    timeRange?: { since?: string; until?: string }
  ): GeneratedReport;
}

/**
 * Markdown report generator
 */
export class MarkdownReportGenerator extends ReportGenerator {
  generateReport(
    framework: string,
    mappings: FrameworkMapping[],
    allAlerts: CodeQLAlert[],
    timeRange?: { since?: string; until?: string }
  ): GeneratedReport {
    const totalAlerts = allAlerts.length;
    const mappedAlerts = mappings.reduce((sum, mapping) => sum + mapping.alertCount, 0);
    const unmappedAlerts = totalAlerts - mappedAlerts;
    const repositoriesScanned = new Set(allAlerts.map(alert => alert.repository?.full_name)).size;

    const content = this.generateMarkdownContent(framework, mappings, {
      totalAlerts,
      repositoriesScanned,
      mappedAlerts,
      unmappedAlerts
    }, timeRange);

    return {
      framework,
      title: `${framework} Compliance Report`,
      generatedAt: new Date().toISOString(),
      timeRange,
      summary: {
        totalAlerts,
        repositoriesScanned,
        mappedAlerts,
        unmappedAlerts
      },
      mappings,
      content
    };
  }

  private generateMarkdownContent(
    framework: string,
    mappings: FrameworkMapping[],
    summary: {
      totalAlerts: number;
      repositoriesScanned: number;
      mappedAlerts: number;
      unmappedAlerts: number;
    },
    timeRange?: { since?: string; until?: string }
  ): string {
    const lines: string[] = [];

    // Header
    lines.push(`# ${framework} Compliance Report`);
    lines.push('');
    lines.push(`**Generated:** ${new Date().toLocaleString()}`);

    if (timeRange) {
      lines.push(`**Time Range:** ${timeRange.since || 'All time'} to ${timeRange.until || 'Now'}`);
    }
    lines.push('');

    // Summary
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(`- **Total CodeQL Alerts:** ${summary.totalAlerts}`);
    lines.push(`- **Repositories Scanned:** ${summary.repositoriesScanned}`);
    lines.push(`- **Alerts Mapped to Framework:** ${summary.mappedAlerts}`);
    lines.push(`- **Unmapped Alerts:** ${summary.unmappedAlerts}`);
    lines.push(`- **Coverage:** ${summary.totalAlerts > 0 ? Math.round((summary.mappedAlerts / summary.totalAlerts) * 100) : 0}%`);
    lines.push('');

    // Framework-specific content
    lines.push(`## ${framework} Analysis`);
    lines.push('');

    if (mappings.length === 0) {
      lines.push('No alerts found that map to this framework.');
      return lines.join('\n');
    }

    // Filter out empty mappings unless requested
    const nonEmptyMappings = mappings.filter(m => m.alertCount > 0);

    if (nonEmptyMappings.length === 0) {
      lines.push('No alerts found that map to this framework.');
      return lines.join('\n');
    }

    // Summary table
    lines.push('### Summary by Category');
    lines.push('');
    lines.push('| Category | Alert Count | CWEs |');
    lines.push('|----------|-------------|------|');

    for (const mapping of nonEmptyMappings) {
      const cweList = mapping.cwes.join(', ');
      lines.push(`| ${mapping.category} | ${mapping.alertCount} | ${cweList} |`);
    }
    lines.push('');

    // Detailed breakdown
    lines.push('### Detailed Breakdown');
    lines.push('');

    for (const mapping of nonEmptyMappings) {
      lines.push(`#### ${mapping.category}`);
      lines.push('');
      lines.push(`**Alert Count:** ${mapping.alertCount}`);
      lines.push(`**CWEs:** ${mapping.cwes.join(', ')}`);
      lines.push('');

      if (mapping.alerts.length > 0) {
        lines.push('**Affected Repositories:**');
        const repoAlertCounts = new Map<string, number>();

        for (const alert of mapping.alerts) {
          const repoName = alert.repository?.full_name || 'Unknown';
          repoAlertCounts.set(repoName, (repoAlertCounts.get(repoName) || 0) + 1);
        }

        const sortedRepos = Array.from(repoAlertCounts.entries())
          .sort(([, a], [, b]) => b - a);

        for (const [repo, count] of sortedRepos) {
          lines.push(`- ${repo}: ${count} alert${count > 1 ? 's' : ''}`);
        }
        lines.push('');

        // Show sample alerts (max 5)
        const sampleAlerts = mapping.alerts.slice(0, 5);
        lines.push('**Sample Alerts:**');

        for (const alert of sampleAlerts) {
          const cwes = CWEExtractor.extractCWEs(alert);
          const cweText = cwes.length > 0 ? ` (${cwes.join(', ')})` : '';
          lines.push(`- **${alert.rule.name}**${cweText}`);
          lines.push(`  - Repository: ${alert.repository?.full_name}`);
          lines.push(`  - File: ${alert.most_recent_instance.location.path}:${alert.most_recent_instance.location.start_line}`);
          lines.push(`  - Severity: ${alert.rule.security_severity_level || alert.rule.severity || 'Unknown'}`);
          lines.push(`  - State: ${alert.state}`);
          lines.push('');
        }

        if (mapping.alerts.length > 5) {
          lines.push(`... and ${mapping.alerts.length - 5} more alerts`);
          lines.push('');
        }
      }

      lines.push('---');
      lines.push('');
    }

    // Recommendations
    lines.push('## Recommendations');
    lines.push('');

    const topCategories = nonEmptyMappings.slice(0, 3);
    if (topCategories.length > 0) {
      lines.push('Based on the analysis, consider prioritizing the following areas:');
      lines.push('');

      for (let i = 0; i < topCategories.length; i++) {
        const mapping = topCategories[i];
        lines.push(`${i + 1}. **${mapping.category}** (${mapping.alertCount} alerts)`);
        lines.push(`   - Focus on addressing ${mapping.cwes.join(', ')} vulnerabilities`);
        lines.push('');
      }
    }

    if (summary.unmappedAlerts > 0) {
      lines.push(`Additionally, ${summary.unmappedAlerts} alerts don't map to ${framework} categories and should be reviewed separately.`);
      lines.push('');
    }

    return lines.join('\n');
  }
}

/**
 * JSON report generator
 */
export class JSONReportGenerator extends ReportGenerator {
  generateReport(
    framework: string,
    mappings: FrameworkMapping[],
    allAlerts: CodeQLAlert[],
    timeRange?: { since?: string; until?: string }
  ): GeneratedReport {
    const totalAlerts = allAlerts.length;
    const mappedAlerts = mappings.reduce((sum, mapping) => sum + mapping.alertCount, 0);
    const unmappedAlerts = totalAlerts - mappedAlerts;
    const repositoriesScanned = new Set(allAlerts.map(alert => alert.repository?.full_name)).size;

    const reportData = {
      framework,
      generatedAt: new Date().toISOString(),
      timeRange,
      summary: {
        totalAlerts,
        repositoriesScanned,
        mappedAlerts,
        unmappedAlerts,
        coverage: totalAlerts > 0 ? Math.round((mappedAlerts / totalAlerts) * 100) : 0
      },
      mappings: mappings.map(mapping => ({
        ...mapping,
        alerts: mapping.alerts.map(alert => ({
          number: alert.number,
          rule: alert.rule,
          state: alert.state,
          repository: alert.repository,
          location: alert.most_recent_instance.location,
          cwes: CWEExtractor.extractCWEs(alert)
        }))
      }))
    };

    return {
      framework,
      title: `${framework} Compliance Report`,
      generatedAt: new Date().toISOString(),
      timeRange,
      summary: {
        totalAlerts,
        repositoriesScanned,
        mappedAlerts,
        unmappedAlerts
      },
      mappings,
      content: JSON.stringify(reportData, null, 2)
    };
  }
}

/**
 * Factory for creating report generators
 */
export class ReportGeneratorFactory {
  static createGenerator(format: string): ReportGenerator {
    switch (format.toLowerCase()) {
      case 'markdown':
      case 'md':
        return new MarkdownReportGenerator();
      case 'json':
        return new JSONReportGenerator();
      default:
        throw new Error(`Unsupported report format: ${format}`);
    }
  }
}
