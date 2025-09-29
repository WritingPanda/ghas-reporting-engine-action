/**
 * CLI types and interfaces for the GHAS Reporting Engine
 */

/**
 * Supported compliance frameworks for reporting
 */
export type ComplianceFramework = 'owasp-top-10' | 'mitre-top-10-kev' | 'sans-top-25';

/**
 * Supported output formats for reports
 */
export type OutputFormat = 'json' | 'markdown' | 'html';

/**
 * Time period options for report generation
 */
export interface TimePeriod {
  /** Number of days to look back, null for all time */
  days?: number;
  /** Custom start date (ISO string) */
  startDate?: string;
  /** Custom end date (ISO string) */
  endDate?: string;
}

/**
 * CLI options interface
 */
export interface CLIOptions {
  /** GitHub API URL (defaults to github.com) */
  githubUrl: string;
  /** GitHub personal access token */
  token: string;
  /** Target organization or enterprise name */
  target: string;
  /** Type of target (organization or enterprise) */
  targetType: 'organization' | 'enterprise';
  /** Compliance frameworks to include in report */
  frameworks: ComplianceFramework[];
  /** Output format for the report */
  output: OutputFormat;
  /** Time period for report generation */
  timePeriod: TimePeriod;
  /** Whether running as a GitHub Action */
  isAction: boolean;
  /** Output file path (optional) */
  outputFile: string | undefined;
  /** Verbose logging */
  verbose: boolean;
}

/**
 * Parsed CLI arguments
 */
export interface ParsedCLIArgs {
  /** GitHub API URL */
  'github-url'?: string;
  /** GitHub token */
  token?: string;
  /** Target organization or enterprise */
  target: string;
  /** Target type */
  'target-type'?: string;
  /** Frameworks (comma-separated) */
  frameworks?: string;
  /** Output format */
  output?: string;
  /** Time period in days */
  days?: string;
  /** Start date */
  'start-date'?: string;
  /** End date */
  'end-date'?: string;
  /** GitHub Action flag */
  action?: boolean;
  /** Output file */
  'output-file'?: string;
  /** Verbose flag */
  verbose?: boolean;
}