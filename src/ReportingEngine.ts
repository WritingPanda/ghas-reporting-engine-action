import { ReportingEngineConfig, GeneratedReport, CodeQLAlert, Repository } from './types';
import { GitHubClient } from './github/GitHubClient';
import { FrameworkAnalyzerFactory } from './frameworks/FrameworkAnalyzer';
import { ReportGeneratorFactory } from './reports/ReportGenerator';
import { Logger } from './utils/Logger';
import { CWEExtractor } from './utils/CWEExtractor';
import { OWASP_TOP_10_MAPPINGS, SANS_TOP_25_MAPPINGS, MITRE_KEV_MAPPINGS } from './frameworks/mappings';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Main reporting engine that orchestrates the GHAS reporting process
 */
export class ReportingEngine {
  private config: ReportingEngineConfig;
  private githubClient: GitHubClient;
  private logger: Logger;
  private summaryText: string = '';

  constructor(config: ReportingEngineConfig) {
    this.config = config;
    this.logger = config.logger;
    this.githubClient = new GitHubClient(config.token, this.logger);
  }

  /**
   * Generate all requested framework reports
   */
  async generateReports(): Promise<GeneratedReport[]> {
    this.logger.info('Starting GHAS Reporting Engine...');

    try {
      // Step 1: Get repositories
      const repositories = await this.getRepositories();

      if (repositories.length === 0) {
        throw new Error('No repositories found or accessible');
      }

      // Step 2: Filter repositories with Advanced Security enabled
      const enabledRepos = await this.githubClient.filterRepositoriesWithAdvancedSecurity(repositories);

      if (enabledRepos.length === 0) {
        this.logger.warn('No repositories found with Advanced Security enabled');
        return [];
      }

      // Step 3: Get CodeQL alerts
      const alerts = await this.getCodeQLAlerts(enabledRepos);

      if (alerts.length === 0) {
        this.logger.warn('No CodeQL alerts found');
        return [];
      }

      // Step 4: Apply date filtering if specified
      const filteredAlerts = this.filterAlertsByDate(alerts);

      // Step 5: Generate reports for each framework
      const reports: GeneratedReport[] = [];

      for (const framework of this.config.frameworks) {
        try {
          this.logger.info(`Generating ${framework.toUpperCase()} report...`);
          const report = await this.generateFrameworkReport(framework, filteredAlerts);
          reports.push(report);
        } catch (error) {
          this.logger.error(`Failed to generate ${framework} report: ${error}`);
        }
      }

      // Step 6: Save reports and generate summary
      await this.saveReports(reports);
      this.generateSummary(reports, filteredAlerts, enabledRepos);

      this.logger.info(`Successfully generated ${reports.length} report(s)`);
      return reports;

    } catch (error) {
      this.logger.error(`Report generation failed: ${error}`);
      throw error;
    }
  }

  /**
   * Get repositories based on configuration
   */
  private async getRepositories(): Promise<Repository[]> {
    let repositories: Repository[] = [];

    if (this.config.organization) {
      repositories = await this.githubClient.getOrganizationRepositories(this.config.organization);
    } else if (this.config.enterprise) {
      repositories = await this.githubClient.getEnterpriseRepositories(this.config.enterprise);
    }

    // Filter by specific repositories if specified
    if (this.config.repositories && this.config.repositories.length > 0) {
      const repoNames = new Set(this.config.repositories);
      repositories = repositories.filter(repo =>
        repoNames.has(repo.name) || repoNames.has(repo.full_name)
      );
    }

    return repositories;
  }

  /**
   * Get CodeQL alerts for repositories
   */
  private async getCodeQLAlerts(repositories: Repository[]): Promise<CodeQLAlert[]> {
    this.logger.info(`Fetching CodeQL alerts from ${repositories.length} repositories...`);

    const alerts = await this.githubClient.getCodeQLAlertsForRepositories(
      repositories,
      'open' // Focus on open alerts for compliance reporting
    );

    this.logger.info(`Found ${alerts.length} CodeQL alerts`);
    return alerts;
  }

  /**
   * Filter alerts by date range if specified
   */
  private filterAlertsByDate(alerts: CodeQLAlert[]): CodeQLAlert[] {
    if (!this.config.sinceDate && !this.config.untilDate) {
      return alerts;
    }

    const since = this.config.sinceDate ? new Date(this.config.sinceDate) : null;
    const until = this.config.untilDate ? new Date(this.config.untilDate) : null;

    return alerts.filter(alert => {
      const alertDate = new Date(alert.created_at);

      if (since && alertDate < since) return false;
      if (until && alertDate > until) return false;

      return true;
    });
  }

  /**
   * Generate a report for a specific framework
   */
  private async generateFrameworkReport(framework: string, alerts: CodeQLAlert[]): Promise<GeneratedReport> {
    // Analyze alerts using the framework analyzer
    const analyzer = FrameworkAnalyzerFactory.createAnalyzer(framework);
    const mappings = analyzer.analyzeAlerts(alerts);

    // Filter out empty mappings unless explicitly requested
    const filteredMappings = this.config.includeEmpty
      ? mappings
      : mappings.filter(m => m.alertCount > 0);

    // Generate the report
    const generator = ReportGeneratorFactory.createGenerator(this.config.outputFormat);
    const report = generator.generateReport(
      analyzer.getFrameworkName(),
      filteredMappings,
      alerts,
      {
        since: this.config.sinceDate,
        until: this.config.untilDate
      }
    );

    return report;
  }

  /**
   * Save reports to files
   */
  private async saveReports(reports: GeneratedReport[]): Promise<void> {
    // Create reports directory
    const reportsDir = path.join(process.cwd(), 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    for (const report of reports) {
      const filename = this.generateReportFilename(report);
      const filepath = path.join(reportsDir, filename);

      try {
        fs.writeFileSync(filepath, report.content, 'utf8');
        this.logger.info(`Saved report: ${filepath}`);
      } catch (error) {
        this.logger.error(`Failed to save report ${filename}: ${error}`);
      }
    }
  }

  /**
   * Generate filename for a report
   */
  private generateReportFilename(report: GeneratedReport): string {
    const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const frameworkName = report.framework.toLowerCase().replace(/\s+/g, '-');
    const extension = this.config.outputFormat === 'json' ? 'json' : 'md';

    return `${frameworkName}-compliance-report-${timestamp}.${extension}`;
  }

  /**
   * Generate summary text for the action output
   */
  private generateSummary(reports: GeneratedReport[], alerts: CodeQLAlert[], repositories: Repository[]): void {
    const lines: string[] = [];

    lines.push('## GHAS Framework Compliance Summary');
    lines.push('');
    lines.push(`**Target:** ${this.config.organization ? `Organization: ${this.config.organization}` : `Enterprise: ${this.config.enterprise}`}`);
    lines.push(`**Repositories Scanned:** ${repositories.length}`);
    lines.push(`**Total CodeQL Alerts:** ${alerts.length}`);
    lines.push(`**Frameworks Analyzed:** ${this.config.frameworks.join(', ').toUpperCase()}`);
    lines.push('');

    if (reports.length > 0) {
      lines.push('### Report Summary by Framework');
      lines.push('');
      lines.push('| Framework | Mapped Alerts | Coverage | Top Issue |');
      lines.push('|-----------|---------------|----------|-----------|');

      for (const report of reports) {
        const coverage = report.summary.totalAlerts > 0
          ? Math.round((report.summary.mappedAlerts / report.summary.totalAlerts) * 100)
          : 0;

        const topIssue = report.mappings
          .filter(m => m.alertCount > 0)
          .sort((a, b) => b.alertCount - a.alertCount)[0];

        const topIssueText = topIssue
          ? `${topIssue.category} (${topIssue.alertCount})`
          : 'None';

        lines.push(`| ${report.framework} | ${report.summary.mappedAlerts} | ${coverage}% | ${topIssueText} |`);
      }
      lines.push('');
    }

    if (alerts.length > 0) {
      const severityCounts = new Map<string, number>();
      for (const alert of alerts) {
        const severity = alert.rule.security_severity_level || alert.rule.severity || 'unknown';
        severityCounts.set(severity, (severityCounts.get(severity) || 0) + 1);
      }

      lines.push('### Alert Distribution by Severity');
      lines.push('');
      for (const [severity, count] of Array.from(severityCounts.entries()).sort(([, a], [, b]) => b - a)) {
        lines.push(`- **${severity.charAt(0).toUpperCase() + severity.slice(1)}:** ${count}`);
      }
      lines.push('');
    }

    lines.push('### Next Steps');
    lines.push('');
    lines.push('1. Review the generated reports in the `reports/` directory');
    lines.push('2. Prioritize remediation based on framework mappings and severity');
    lines.push('3. Set up regular monitoring to track progress over time');
    lines.push('');

    // Track which alerts have been included in framework reports
    const mappedAlerts = new Set<number>();
    for (const report of reports) {
      for (const mapping of report.mappings) {
        for (const alert of mapping.alerts) {
          mappedAlerts.add(alert.number);
        }
      }
    }

    // Add detailed alert listings by CWE for each framework
    for (const report of reports) {
      lines.push(`<details>`);
      lines.push(`<summary><h3>📋 Detailed Alerts for ${report.framework} (Click to expand)</h3></summary>`);
      lines.push('');
      for (const mapping of report.mappings) {
        if (mapping.alertCount === 0) continue;
        // Group alerts by CWE
        const cweToAlerts: Record<string, CodeQLAlert[]> = {};
        for (const alert of mapping.alerts) {
          // Use CWEExtractor for consistent CWE extraction
          const cwes = CWEExtractor.extractCWEs(alert);
          // Only process alerts that have CWEs mapped to this framework
          if (cwes.length === 0) continue;
          for (const cweRaw of cwes) {
            const cwe = typeof cweRaw === 'string' && cweRaw ? cweRaw : '';
            if (!cwe) continue;

            // Check if this CWE is actually mapped to the current framework
            if (this.isCWEMappedToFramework(cwe, report.framework)) {
              if (!cweToAlerts[cwe]) cweToAlerts[cwe] = [];
              cweToAlerts[cwe].push(alert);
            }
          }
        }
        // Output each CWE and its alerts grouped by repository
        for (const [cwe, cweAlerts] of Object.entries(cweToAlerts)) {
          const capitalizedCwe = cwe.toUpperCase();
          const cweName = this.getCWEName(cwe);

          lines.push(`<details>`);
          lines.push(`<summary><strong>${capitalizedCwe}: ${cweName}</strong> - ${cweAlerts.length} alert${cweAlerts.length === 1 ? '' : 's'}</summary>`);
          lines.push('');

          // Group alerts by repository
          const repoToAlerts: Record<string, CodeQLAlert[]> = {};
          for (const alert of cweAlerts) {
            const repoName = alert.repository?.full_name || 'unknown';
            if (!repoToAlerts[repoName]) repoToAlerts[repoName] = [];
            repoToAlerts[repoName].push(alert);
          }

          // Output alerts grouped by repository
          for (const [repoName, repoAlerts] of Object.entries(repoToAlerts)) {
            lines.push(`  **${repoName}:**`);
            for (const alert of repoAlerts) {
              lines.push(`- ${alert.rule.description} - [${alert.rule.name} (#${alert.number})](${alert.html_url})`);
            }
            lines.push('');
          }
          lines.push(`</details>`);
          lines.push('');
        }
      }
      lines.push(`</details>`);
      lines.push('');
    }

    // Add section for alerts not represented in any framework
    const unmappedAlerts = alerts.filter(alert => !mappedAlerts.has(alert.number));
    if (unmappedAlerts.length > 0) {
      lines.push(`<details>`);
      lines.push(`<summary><h3>🔍 Additional Alerts Not Represented in Frameworks (Click to expand)</h3></summary>`);
      lines.push('');
      lines.push(`**${unmappedAlerts.length} alert${unmappedAlerts.length === 1 ? '' : 's'} found that do${unmappedAlerts.length === 1 ? 'es' : ''} not map to any of the analyzed frameworks (${this.config.frameworks.join(', ').toUpperCase()})**`);
      lines.push('');
      lines.push('These alerts may represent:');
      lines.push('- Security issues with CWEs not covered by the selected frameworks');
      lines.push('- Custom or newer security rules without established framework mappings');
      lines.push('- Language-specific vulnerabilities outside standard categories');
      lines.push('');

      // Group unmapped alerts by repository
      const repoToUnmappedAlerts: Record<string, CodeQLAlert[]> = {};
      for (const alert of unmappedAlerts) {
        const repoName = alert.repository?.full_name || 'unknown';
        if (!repoToUnmappedAlerts[repoName]) repoToUnmappedAlerts[repoName] = [];
        repoToUnmappedAlerts[repoName].push(alert);
      }

      // Output unmapped alerts grouped by repository
      for (const [repoName, repoAlerts] of Object.entries(repoToUnmappedAlerts)) {
        lines.push(`**${repoName}:** (${repoAlerts.length} alert${repoAlerts.length === 1 ? '' : 's'})`);
        for (const alert of repoAlerts) {
          const cwes = CWEExtractor.extractCWEs(alert);
          const cweText = cwes.length > 0 ? ` [${cwes.join(', ')}]` : ' [No CWE]';
          lines.push(`- ${alert.rule.description}${cweText} - [${alert.rule.name} (#${alert.number})](${alert.html_url})`);
        }
        lines.push('');
      }
      lines.push(`</details>`);
      lines.push('');
    }

    this.summaryText = lines.join('\n');
  }

  /**
   * Get the summary text for action output
   */
  getSummaryText(): string {
    return this.summaryText;
  }

  /**
   * Get CWE name from mappings - only for CWEs that are mapped to frameworks
   */
  private getCWEName(cwe: string): string {
    // Normalize CWE format for comparison
    const normalizeCWE = (cweId: string): string => {
      const match = cweId.match(/CWE-(\d+)/i);
      if (match) {
        const number = parseInt(match[1], 10);
        return `CWE-${number.toString().padStart(3, '0')}`;
      }
      return cweId;
    };

    const normalizedInputCwe = normalizeCWE(cwe);

    // Search in OWASP mappings first (most comprehensive)
    for (const category of Object.values(OWASP_TOP_10_MAPPINGS)) {
      for (const cweInfo of category.cwes) {
        const normalizedMappingCwe = normalizeCWE(cweInfo.cwe);
        if (normalizedMappingCwe === normalizedInputCwe) {
          return cweInfo.name;
        }
      }
    }

    // Search in SANS mappings
    for (const mapping of Object.values(SANS_TOP_25_MAPPINGS)) {
      const normalizedMappingCwe = normalizeCWE(mapping.cwe);
      if (normalizedMappingCwe === normalizedInputCwe) {
        return mapping.name;
      }
    }

    // Search in MITRE KEV mappings
    for (const mapping of Object.values(MITRE_KEV_MAPPINGS)) {
      const normalizedMappingCwe = normalizeCWE(mapping.cwe);
      if (normalizedMappingCwe === normalizedInputCwe) {
        return mapping.name;
      }
    }

    // If not found in any mappings, return a generic name
    return 'Security Vulnerability';
  }

  /**
   * Check if a CWE is mapped to a specific framework
   */
  private isCWEMappedToFramework(cwe: string, framework: string): boolean {
    // Normalize CWE format for comparison
    const normalizeCWE = (cweId: string): string => {
      const match = cweId.match(/CWE-(\d+)/i);
      if (match) {
        const number = parseInt(match[1], 10);
        return `CWE-${number.toString().padStart(3, '0')}`;
      }
      return cweId;
    };

    const normalizedInputCwe = normalizeCWE(cwe);
    const frameworkLower = framework.toLowerCase();

    // Check OWASP mappings
    if (frameworkLower.includes('owasp')) {
      for (const category of Object.values(OWASP_TOP_10_MAPPINGS)) {
        for (const cweInfo of category.cwes) {
          const normalizedMappingCwe = normalizeCWE(cweInfo.cwe);
          if (normalizedMappingCwe === normalizedInputCwe) {
            return true;
          }
        }
      }
    }

    // Check SANS mappings
    if (frameworkLower.includes('sans')) {
      for (const mapping of Object.values(SANS_TOP_25_MAPPINGS)) {
        const normalizedMappingCwe = normalizeCWE(mapping.cwe);
        if (normalizedMappingCwe === normalizedInputCwe) {
          return true;
        }
      }
    }

    // Check MITRE KEV mappings
    if (frameworkLower.includes('kev') || frameworkLower.includes('mitre')) {
      for (const mapping of Object.values(MITRE_KEV_MAPPINGS)) {
        const normalizedMappingCwe = normalizeCWE(mapping.cwe);
        if (normalizedMappingCwe === normalizedInputCwe) {
          return true;
        }
      }
    }

    return false;
  }
}
