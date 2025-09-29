/**
 * Main entry point for the GHAS Reporting Engine CLI
 */

import { GitHubClient } from './clients';
import { logger, parseCLIArguments } from './utils';
import { AlertTarget, GitHubClientConfig, CLIOptions, ProcessedAlert } from './types';

/**
 * Initialize and test the GitHub client
 */
async function initializeGitHubClient(token: string, githubUrl: string = 'https://api.github.com'): Promise<GitHubClient> {
  const config: GitHubClientConfig = {
    token,
    userAgent: 'GHAS-Reporting-Engine/1.0.0',
    baseUrl: githubUrl,
  };

  const client = new GitHubClient(config);

  // Test the connection
  const isConnected = await client.testConnection();
  if (!isConnected) {
    throw new Error('Failed to connect to GitHub API. Please check your token and URL.');
  }

  return client;
}

/**
 * Fetch alerts based on CLI options
 */
async function fetchAlerts(client: GitHubClient, options: CLIOptions): Promise<ProcessedAlert[]> {
  const target: AlertTarget = {
    type: options.targetType,
    name: options.target,
  };

  logger.info(`Fetching alerts for ${options.targetType}: ${options.target}`);

  let alerts: ProcessedAlert[] = [];

  if (options.targetType === 'organization') {
    alerts = await client.fetchOrganizationAlerts(target);
  } else {
    // Enterprise alerts would be handled here
    // For now, we'll throw an error as enterprise support isn't implemented yet
    throw new Error('Enterprise alert fetching is not yet implemented');
  }

  // Filter by time period if specified
  if (options.timePeriod.days || options.timePeriod.startDate || options.timePeriod.endDate) {
    alerts = filterAlertsByTimePeriod(alerts, options.timePeriod);
  }

  logger.info(`Found ${alerts.length} alerts matching criteria`);
  return alerts;
}

/**
 * Filter alerts by time period
 */
function filterAlertsByTimePeriod(alerts: ProcessedAlert[], timePeriod: CLIOptions['timePeriod']): ProcessedAlert[] {
  const now = new Date();
  let startDate: Date | null = null;
  let endDate: Date | null = null;

  if (timePeriod.days) {
    startDate = new Date(now.getTime() - (timePeriod.days * 24 * 60 * 60 * 1000));
  }

  if (timePeriod.startDate) {
    startDate = new Date(timePeriod.startDate);
  }

  if (timePeriod.endDate) {
    endDate = new Date(timePeriod.endDate);
  }

  return alerts.filter(alert => {
    const alertDate = new Date(alert.alert.created_at);

    if (startDate && alertDate < startDate) {
      return false;
    }

    if (endDate && alertDate > endDate) {
      return false;
    }

    return true;
  });
}

/**
 * Generate report output based on format
 */
async function generateReport(alerts: ProcessedAlert[], options: CLIOptions): Promise<string> {
  const reportData = {
    generatedAt: new Date().toISOString(),
    target: {
      type: options.targetType,
      name: options.target,
    },
    frameworks: options.frameworks,
    timePeriod: options.timePeriod,
    totalAlerts: alerts.length,
    alerts: alerts,
  };

  switch (options.output) {
    case 'json':
      return JSON.stringify(reportData, null, 2);

    case 'markdown':
      return generateMarkdownReport(reportData);

    case 'html':
      return generateHTMLReport(reportData);

    default:
      throw new Error(`Unsupported output format: ${options.output}`);
  }
}

/**
 * Generate Markdown report (placeholder implementation)
 */
function generateMarkdownReport(data: any): string {
  return `# GHAS Security Report

**Generated:** ${data.generatedAt}
**Target:** ${data.target.type} - ${data.target.name}
**Frameworks:** ${data.frameworks.join(', ')}
**Total Alerts:** ${data.totalAlerts}

## Summary

This report contains ${data.totalAlerts} security alerts from GitHub Advanced Security.

_Note: Detailed markdown report generation will be implemented in the next phase._
`;
}

/**
 * Generate HTML report (placeholder implementation)
 */
function generateHTMLReport(data: any): string {
  return `<!DOCTYPE html>
<html>
<head>
    <title>GHAS Security Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #333; margin-bottom: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GHAS Security Report</h1>
        <p><strong>Generated:</strong> ${data.generatedAt}</p>
        <p><strong>Target:</strong> ${data.target.type} - ${data.target.name}</p>
        <p><strong>Frameworks:</strong> ${data.frameworks.join(', ')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Alerts: <strong>${data.totalAlerts}</strong></p>
    </div>
    
    <p><em>Note: Detailed HTML report generation will be implemented in the next phase.</em></p>
</body>
</html>`;
}

/**
 * Output report to file or stdout
 */
async function outputReport(report: string, options: CLIOptions): Promise<void> {
  if (options.outputFile) {
    const fs = await import('fs');
    await fs.promises.writeFile(options.outputFile, report, 'utf8');
    logger.info(`Report saved to: ${options.outputFile}`);
  } else {
    console.log(report);
  }

  // If running as GitHub Action, also add to action summary
  if (options.isAction && process.env.GITHUB_STEP_SUMMARY) {
    const fs = await import('fs');
    let summaryContent = report;

    // Convert to markdown for action summary if not already markdown
    if (options.output !== 'markdown') {
      summaryContent = `# GHAS Security Report\n\nGenerated at: ${new Date().toISOString()}\n\nSee attached artifact for full report.`;
    }

    await fs.promises.appendFile(process.env.GITHUB_STEP_SUMMARY, summaryContent, 'utf8');
    logger.info('Report added to GitHub Action summary');
  }
}

/**
 * Main CLI function
 */
async function main(): Promise<void> {
  try {
    // Parse CLI arguments
    const options = parseCLIArguments();

    logger.info('Starting GHAS Reporting Engine', {
      target: `${options.targetType}:${options.target}`,
      frameworks: options.frameworks,
      output: options.output,
      isAction: options.isAction,
    });

    // Initialize GitHub client
    const client = await initializeGitHubClient(options.token, options.githubUrl);

    // Check rate limits
    const rateLimit = await client.getRateLimit();
    logger.info('GitHub API Rate Limit', {
      remaining: rateLimit.remaining,
      limit: rateLimit.limit,
      reset: rateLimit.reset.toISOString(),
    });

    // Fetch alerts
    const alerts = await fetchAlerts(client, options);

    // Generate report
    const report = await generateReport(alerts, options);

    // Output report
    await outputReport(report, options);

    logger.info('GHAS Reporting Engine completed successfully');

  } catch (error) {
    logger.error('GHAS Reporting Engine failed', error as Error);
    process.exit(1);
  }
}

// Export for testing and modular usage
export { initializeGitHubClient, main };
export * from './types';
export * from './clients';
export * from './utils';

// Run main function if this file is executed directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Unhandled error in main', error);
    process.exit(1);
  });
}