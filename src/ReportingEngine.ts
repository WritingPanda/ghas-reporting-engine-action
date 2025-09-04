import { ReportingEngineConfig, GeneratedReport, CodeQLAlert, Repository } from './types';
import { GitHubClient } from './github/GitHubClient';
import { FrameworkAnalyzerFactory } from './frameworks/FrameworkAnalyzer';
import { ReportGeneratorFactory } from './reports/ReportGenerator';
import { Logger } from './utils/Logger';
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

    // Add detailed alert listings by CWE for each framework
    for (const report of reports) {
      lines.push(`### Detailed Alerts for ${report.framework}`);
      for (const mapping of report.mappings) {
        if (mapping.alertCount === 0) continue;
        // Group alerts by CWE
        const cweToAlerts: Record<string, CodeQLAlert[]> = {};
        for (const alert of mapping.alerts) {
          // Extract CWEs for this alert
          const cwes = alert.rule.tags?.filter(tag => tag.match(/CWE-\d+/i))?.map(tag => tag.match(/CWE-\d+/i)?.[0]) || [];
          // Fallback to extracting from name/description/classifications
          if (cwes.length === 0 && alert.rule.name) {
            const matches = alert.rule.name.match(/CWE-\d+/gi);
            if (matches) cwes.push(...matches);
          }
          if (cwes.length === 0 && alert.rule.description) {
            const matches = alert.rule.description.match(/CWE-\d+/gi);
            if (matches) cwes.push(...matches);
          }
          if (cwes.length === 0 && alert.most_recent_instance.classifications) {
            for (const classification of alert.most_recent_instance.classifications) {
              const match = classification.match(/CWE-\d+/i);
              if (match) cwes.push(match[0]);
            }
          }
          // If no CWE found, group under 'Unmapped'
          if (cwes.length === 0) cwes.push('Unmapped');
          for (const cweRaw of cwes) {
            const cwe = typeof cweRaw === 'string' && cweRaw ? cweRaw : 'Unmapped';
            if (!cweToAlerts[cwe]) cweToAlerts[cwe] = [];
            cweToAlerts[cwe].push(alert);
          }
        }
        // Output each CWE and its alerts grouped by repository
        for (const [cwe, cweAlerts] of Object.entries(cweToAlerts)) {
          const capitalizedCwe = cwe === 'Unmapped' ? 'Unmapped' : cwe.toUpperCase();
          const cweName = cwe === 'Unmapped' ? 'Alerts without CWE mapping' : this.getCWEName(cwe);
          lines.push(`#### ${capitalizedCwe}: ${cweName} - ${cweAlerts.length} alert${cweAlerts.length === 1 ? '' : 's'}`);
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
            lines.push(`**${repoName}:**`);
            for (const alert of repoAlerts) {
              lines.push(`${alert.rule.description} (${alert.rule.name}) - [${alert.html_url}](${alert.html_url})`);
            }
            lines.push('');
          }
        }
      }
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
   * Get CWE name from mappings
   */
  private getCWEName(cwe: string): string {
    // Create a comprehensive CWE name mapping
    const cweNames: Record<string, string> = {
      // From SANS Top 25
      'CWE-787': 'Out-of-bounds Write',
      'CWE-79': 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
      'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
      'CWE-416': 'Use After Free',
      'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
      'CWE-20': 'Improper Input Validation',
      'CWE-125': 'Out-of-bounds Read',
      'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
      'CWE-352': 'Cross-Site Request Forgery (CSRF)',
      'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
      'CWE-862': 'Missing Authorization',
      'CWE-476': 'NULL Pointer Dereference',
      'CWE-287': 'Improper Authentication',
      'CWE-190': 'Integer Overflow or Wraparound',
      'CWE-502': 'Deserialization of Untrusted Data',
      'CWE-77': 'Improper Neutralization of Special Elements used in a Command (Command Injection)',
      'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
      'CWE-798': 'Use of Hard-coded Credentials',
      'CWE-918': 'Server-Side Request Forgery (SSRF)',
      'CWE-306': 'Missing Authentication for Critical Function',
      'CWE-362': 'Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)',
      'CWE-269': 'Improper Privilege Management',
      'CWE-94': 'Improper Control of Generation of Code (Code Injection)',
      'CWE-863': 'Incorrect Authorization',
      'CWE-276': 'Incorrect Default Permissions',

      // From MITRE KEV (additional ones not in SANS)
      'CWE-843': 'Access of Resource Using Incompatible Type (Type Confusion)',

      // From OWASP Top 10 (additional common ones)
      'CWE-113': 'Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)',
      'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
      'CWE-284': 'Improper Access Control',
      'CWE-285': 'Improper Authorization',
      'CWE-319': 'Cleartext Transmission of Sensitive Information',
      'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
      'CWE-601': 'URL Redirection to Untrusted Site (Open Redirect)',
      'CWE-74': 'Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)',
      'CWE-259': 'Use of Hard-coded Password',
      'CWE-116': 'Improper Encoding or Escaping of Output',
      'CWE-209': 'Generation of Error Message Containing Sensitive Information',
      'CWE-311': 'Missing Encryption of Sensitive Data',
      'CWE-330': 'Use of Insufficiently Random Values',
      'CWE-522': 'Insufficiently Protected Credentials',
      'CWE-611': 'Improper Restriction of XML External Entity Reference',
      'CWE-117': 'Improper Output Neutralization for Logs',
      'CWE-532': 'Insertion of Sensitive Information into Log File'
    };

    // Search in comprehensive mapping first
    if (cweNames[cwe]) {
      return cweNames[cwe];
    }

    // Search in SANS mappings
    for (const mapping of Object.values(SANS_TOP_25_MAPPINGS)) {
      if (mapping.cwe === cwe) {
        return mapping.name;
      }
    }

    // Search in MITRE KEV mappings
    for (const mapping of Object.values(MITRE_KEV_MAPPINGS)) {
      if (mapping.cwe === cwe) {
        return mapping.name;
      }
    }

    // If not found in any mappings, return a generic name
    return 'Security Vulnerability';
  }
}
