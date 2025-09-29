/**
 * Common types used across the application
 */

import { TimePeriod } from './cli';

export * from './cli';
export * from './github';

/**
 * Application configuration
 */
export interface AppConfig {
  github: {
    token: string;
    baseUrl?: string;
  };
  target: {
    type: 'organization' | 'enterprise';
    name: string;
    repositories?: string[];
  };
  reporting: {
    types: ReportType[];
    format: ReportFormat;
    timePeriod?: TimePeriod;
    outputPath?: string;
  };
}

/**
 * Report types supported by the application
 */
export type ReportType = 'owasp-top-10' | 'sans-top-25' | 'mitre-kev';

/**
 * Report output formats
 */
export type ReportFormat = 'json' | 'csv' | 'html';



/**
 * Logging levels
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Application error with context
 */
export interface AppError extends Error {
  code?: string;
  context?: Record<string, unknown>;
}