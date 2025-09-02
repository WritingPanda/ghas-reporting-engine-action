import { Logger } from './utils/Logger';

/**
 * Configuration options for the ReportingEngine
 */
export interface ReportingEngineConfig {
  token: string;
  organization?: string;
  enterprise?: string;
  frameworks: string[];
  outputFormat: string;
  includeEmpty: boolean;
  sinceDate?: string;
  untilDate?: string;
  repositories?: string[];
  logger: Logger;
}

/**
 * Represents a CodeQL alert from GitHub Advanced Security
 */
export interface CodeQLAlert {
  number: number;
  rule: {
    id: string;
    name: string;
    description: string;
    security_severity_level?: string;
    severity?: string;
    tags?: string[];
  };
  tool: {
    name: string;
    version?: string;
  };
  most_recent_instance: {
    ref: string;
    analysis_key: string;
    environment: string;
    category: string;
    state: string;
    commit_sha: string;
    message: {
      text: string;
    };
    location: {
      path: string;
      start_line: number;
      end_line: number;
      start_column: number;
      end_column: number;
    };
    classifications?: string[];
  };
  state: string;
  fixed_at?: string;
  dismissed_at?: string;
  dismissed_by?: any;
  dismissed_reason?: string;
  dismissed_comment?: string;
  created_at: string;
  updated_at: string;
  url: string;
  html_url: string;
  repository?: {
    name: string;
    full_name: string;
    owner: {
      login: string;
    };
  };
  instances_url: string;
}

/**
 * CWE (Common Weakness Enumeration) information
 */
export interface CWEInfo {
  id: string;
  name: string;
  description?: string;
}

/**
 * Framework compliance mapping result
 */
export interface FrameworkMapping {
  framework: string;
  category: string;
  rank?: number;
  cwes: string[];
  alertCount: number;
  alerts: CodeQLAlert[];
}

/**
 * Generated report structure
 */
export interface GeneratedReport {
  framework: string;
  title: string;
  generatedAt: string;
  timeRange?: {
    since?: string;
    until?: string;
  };
  summary: {
    totalAlerts: number;
    repositoriesScanned: number;
    mappedAlerts: number;
    unmappedAlerts: number;
  };
  mappings: FrameworkMapping[];
  content: string;
}

/**
 * Repository information
 */
export interface Repository {
  name: string;
  full_name: string;
  owner: {
    login: string;
  };
  private: boolean;
  security_and_analysis?: {
    advanced_security?: {
      status: string;
    };
  };
}

/**
 * Supported frameworks
 */
export type SupportedFramework = 'owasp' | 'sans' | 'kev';

/**
 * Output formats
 */
export type OutputFormat = 'markdown' | 'json' | 'csv';
