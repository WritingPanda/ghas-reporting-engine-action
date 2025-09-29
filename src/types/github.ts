/**
 * Type definitions for GitHub Code Scanning API responses
 */

export interface CodeScanningAlert {
  number: number;
  created_at: string;
  updated_at?: string;
  url: string;
  html_url: string;
  state: 'open' | 'dismissed' | 'fixed' | null;
  dismissed_by?: {
    login: string;
    id: number;
    type: string;
  } | null;
  dismissed_at?: string | null;
  dismissed_reason?: 'false positive' | 'won\'t fix' | 'used in tests' | null;
  dismissed_comment?: string | null;
  rule: AlertRule;
  tool: AlertTool;
  most_recent_instance: AlertInstance;
  instances_url: string;
}

export interface AlertRule {
  id?: string | null;
  severity?: 'note' | 'warning' | 'error' | 'none' | null;
  security_severity_level?: 'low' | 'medium' | 'high' | 'critical' | null;
  tags?: string[] | null;
  description?: string;
  name?: string;
  full_description?: string;
  help?: string | null;
  help_uri?: string | null;
}

export interface AlertTool {
  name?: string;
  guid?: string | null;
  version?: string | null;
}

export interface AlertInstance {
  ref?: string;
  analysis_key?: string;
  category?: string;
  environment?: string;
  state?: 'open' | 'dismissed' | 'fixed' | null;
  commit_sha?: string;
  location?: AlertLocation;
  message?: AlertMessage;
  html_url?: string;
  classifications?: (string | null)[];
}

export interface AlertLocation {
  path?: string;
  start_line?: number;
  end_line?: number;
  start_column?: number;
  end_column?: number;
}

export interface AlertMessage {
  text?: string;
}

/**
 * Extracted CWE information from alert tags
 */
export interface CWEInfo {
  id: string;
  number: number;
  name?: string;
  description?: string;
}

/**
 * Processed alert data with extracted CWE information
 */
export interface ProcessedAlert {
  alert: CodeScanningAlert;
  cwes: CWEInfo[];
  repository: string;
  organization: string;
}

/**
 * Pagination options for GitHub API requests
 */
export interface PaginationOptions {
  per_page?: number;
  page?: number;
}

/**
 * Filter options for code scanning alerts
 */
export interface AlertFilters {
  state?: 'open' | 'dismissed' | 'fixed';
  severity?: 'critical' | 'high' | 'medium' | 'low';
  tool_name?: string;
  ref?: string;
  pr?: number;
  updated_after?: string;
  updated_before?: string;
}

/**
 * GitHub API response wrapper for paginated results
 */
export interface PaginatedResponse<T> {
  data: T[];
  hasNextPage: boolean;
  nextPage?: number;
  totalCount?: number;
}

/**
 * Configuration for GitHub client
 */
export interface GitHubClientConfig {
  token: string;
  baseUrl?: string;
  userAgent?: string;
}

/**
 * Organization or enterprise target for alert fetching
 */
export interface AlertTarget {
  type: 'organization' | 'enterprise';
  name: string;
  repositories?: string[]; // Optional filter for specific repositories
}