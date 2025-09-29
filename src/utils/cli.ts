/**
 * CLI utilities for argument parsing and validation
 */

import { Command } from 'commander';
import { CLIOptions, ComplianceFramework, OutputFormat, ParsedCLIArgs, TimePeriod } from '../types';
import { logger } from './logger';

/**
 * Available compliance frameworks
 */
export const AVAILABLE_FRAMEWORKS: ComplianceFramework[] = [
  'owasp-top-10',
  'mitre-top-10-kev',
  'sans-top-25'
];

/**
 * Available output formats
 */
export const AVAILABLE_FORMATS: OutputFormat[] = [
  'json',
  'markdown',
  'html'
];

/**
 * Parse frameworks from comma-separated string
 */
function parseFrameworks(frameworksStr: string): ComplianceFramework[] {
  const frameworks = frameworksStr
    .split(',')
    .map(f => f.trim().toLowerCase() as ComplianceFramework)
    .filter(f => AVAILABLE_FRAMEWORKS.includes(f));

  if (frameworks.length === 0) {
    throw new Error(`Invalid frameworks. Available options: ${AVAILABLE_FRAMEWORKS.join(', ')}`);
  }

  return frameworks;
}

/**
 * Parse time period from CLI arguments
 */
function parseTimePeriod(args: ParsedCLIArgs): TimePeriod {
  const timePeriod: TimePeriod = {};

  if (args.days) {
    const days = parseInt(args.days, 10);
    if (isNaN(days) || days < 1) {
      throw new Error('Days must be a positive integer');
    }
    timePeriod.days = days;
  }

  if (args['start-date']) {
    const startDate = new Date(args['start-date']);
    if (isNaN(startDate.getTime())) {
      throw new Error('Invalid start date format. Use ISO format (YYYY-MM-DD)');
    }
    timePeriod.startDate = args['start-date'];
  }

  if (args['end-date']) {
    const endDate = new Date(args['end-date']);
    if (isNaN(endDate.getTime())) {
      throw new Error('Invalid end date format. Use ISO format (YYYY-MM-DD)');
    }
    timePeriod.endDate = args['end-date'];
  }

  // Validate date range
  if (timePeriod.startDate && timePeriod.endDate) {
    const start = new Date(timePeriod.startDate);
    const end = new Date(timePeriod.endDate);
    if (start >= end) {
      throw new Error('Start date must be before end date');
    }
  }

  return timePeriod;
}

/**
 * Validate and parse CLI options
 */
export function validateCLIOptions(args: ParsedCLIArgs): CLIOptions {
  // Required arguments
  if (!args.target) {
    throw new Error('Target organization or enterprise is required');
  }

  // GitHub token (from args or environment)
  const token = args.token || process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GitHub token is required. Provide via --token or GITHUB_TOKEN environment variable');
  }

  // Parse frameworks
  const frameworksStr = args.frameworks || 'owasp-top-10';
  const frameworks = parseFrameworks(frameworksStr);

  // Validate output format
  const output = (args.output || 'json') as OutputFormat;
  if (!AVAILABLE_FORMATS.includes(output)) {
    throw new Error(`Invalid output format. Available options: ${AVAILABLE_FORMATS.join(', ')}`);
  }

  // Validate target type
  const targetType = (args['target-type'] || 'organization') as 'organization' | 'enterprise';
  if (!['organization', 'enterprise'].includes(targetType)) {
    throw new Error('Target type must be either "organization" or "enterprise"');
  }

  // Parse time period
  const timePeriod = parseTimePeriod(args);

  const options: CLIOptions = {
    githubUrl: args['github-url'] || 'https://api.github.com',
    token,
    target: args.target,
    targetType,
    frameworks,
    output,
    timePeriod,
    isAction: args.action || false,
    outputFile: args['output-file'],
    verbose: args.verbose || false
  };

  return options;
}

/**
 * Create and configure the CLI program
 */
export function createCLIProgram(): Command {
  const program = new Command();

  program
    .name('ghas-reporting-engine')
    .description('Generate security compliance reports from GitHub Advanced Security findings')
    .version('1.0.0')
    .requiredOption('-t, --target <name>', 'target organization or enterprise name')
    .option('--github-url <url>', 'GitHub API URL', 'https://api.github.com')
    .option('--token <token>', 'GitHub personal access token (can also use GITHUB_TOKEN env var)')
    .option('--target-type <type>', 'target type: organization or enterprise', 'organization')
    .option(
      '-f, --frameworks <frameworks>',
      `compliance frameworks (comma-separated): ${AVAILABLE_FRAMEWORKS.join(', ')}`,
      'owasp-top-10'
    )
    .option(
      '-o, --output <format>',
      `output format: ${AVAILABLE_FORMATS.join(', ')}`,
      'json'
    )
    .option('--days <days>', 'number of days to look back (default: all time)')
    .option('--start-date <date>', 'start date for report (ISO format: YYYY-MM-DD)')
    .option('--end-date <date>', 'end date for report (ISO format: YYYY-MM-DD)')
    .option('--output-file <file>', 'output file path (default: stdout)')
    .option('--action', 'running as GitHub Action', false)
    .option('-v, --verbose', 'verbose logging', false);

  return program;
}

/**
 * Parse and validate CLI arguments
 */
export function parseCLIArguments(argv?: string[]): CLIOptions {
  const program = createCLIProgram();

  try {
    program.parse(argv);
    const args = program.opts() as ParsedCLIArgs;

    // Set log level based on verbose flag
    if (args.verbose) {
      logger.setLogLevel('debug');
    }

    return validateCLIOptions(args);
  } catch (error) {
    logger.error('CLI argument validation failed', error as Error);
    program.help();
    process.exit(1);
  }
}