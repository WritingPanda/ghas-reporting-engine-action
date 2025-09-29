/**
 * GitHub API client for fetching code scanning alerts
 */

import { Octokit } from '@octokit/rest';
import { createTokenAuth } from '@octokit/auth-token';
import {
  ProcessedAlert,
  GitHubClientConfig,
  AlertTarget,
  AlertFilters,
} from '../types';
import { extractCWEsFromTags } from '../utils/cwe';
import { logger } from '../utils/logger';

export class GitHubClient {
  private octokit: Octokit;
  private config: GitHubClientConfig;

  constructor(config: GitHubClientConfig) {
    this.config = config;

    const auth = createTokenAuth(config.token);

    this.octokit = new Octokit({
      auth: config.token,
      baseUrl: config.baseUrl || 'https://api.github.com',
      userAgent: config.userAgent || 'GHAS-Reporting-Engine/1.0.0',
    });
  }

  /**
   * Fetch all code scanning alerts for an organization
   * @param target Organization or enterprise target
   * @param filters Optional filters for alerts
   * @returns Array of processed alerts with CWE information
   */
  async fetchOrganizationAlerts(
    target: AlertTarget,
    filters?: AlertFilters
  ): Promise<ProcessedAlert[]> {
    logger.info(`Fetching alerts for ${target.type}: ${target.name}`);

    if (target.type === 'enterprise') {
      return this.fetchEnterpriseAlerts(target, filters);
    } else {
      return this.fetchOrgAlerts(target, filters);
    }
  }

  /**
   * Fetch alerts for all repositories in an organization
   */
  private async fetchOrgAlerts(
    target: AlertTarget,
    filters?: AlertFilters
  ): Promise<ProcessedAlert[]> {
    const repositories = target.repositories || await this.getOrganizationRepositories(target.name);
    const allAlerts: ProcessedAlert[] = [];

    logger.info(`Found ${repositories.length} repositories to scan`);

    for (const repo of repositories) {
      try {
        logger.debug(`Fetching alerts for repository: ${repo}`);
        const repoAlerts = await this.fetchRepositoryAlerts(target.name, repo, filters);
        allAlerts.push(...repoAlerts);

        // Add a small delay to avoid rate limiting
        await this.delay(100);
      } catch (error) {
        logger.warn(`Failed to fetch alerts for repository ${repo}`, { error: (error as Error).message });
        continue;
      }
    }

    logger.info(`Fetched ${allAlerts.length} total alerts`);
    return allAlerts;
  }

  /**
   * Fetch alerts for enterprise (placeholder - requires GitHub Enterprise Cloud)
   */
  private async fetchEnterpriseAlerts(
    target: AlertTarget,
    filters?: AlertFilters
  ): Promise<ProcessedAlert[]> {
    // Enterprise API endpoints are different and require GitHub Enterprise Cloud
    // This is a placeholder implementation
    logger.warn('Enterprise alert fetching not yet implemented');
    return [];
  }

  /**
   * Fetch code scanning alerts for a specific repository
   */
  async fetchRepositoryAlerts(
    owner: string,
    repo: string,
    filters?: AlertFilters
  ): Promise<ProcessedAlert[]> {
    const alerts: ProcessedAlert[] = [];
    let page = 1;
    const perPage = 100; // GitHub API maximum

    while (true) {
      try {
        logger.debug(`Fetching page ${page} for ${owner}/${repo}`);

        const requestParams: any = {
          owner,
          repo,
          per_page: perPage,
          page,
        };

        if (filters?.state) requestParams.state = filters.state;
        if (filters?.severity) requestParams.severity = filters.severity;
        if (filters?.tool_name) requestParams.tool_name = filters.tool_name;
        if (filters?.ref) requestParams.ref = filters.ref;

        const response = await this.octokit.rest.codeScanning.listAlertsForRepo(requestParams);

        if (response.data.length === 0) {
          break;
        }

        // Process alerts and extract CWE information
        for (const alert of response.data) {
          const cwes = extractCWEsFromTags(alert.rule.tags || []);

          // Apply time-based filters if specified
          if (filters?.updated_after || filters?.updated_before) {
            const alertDate = new Date(alert.updated_at || alert.created_at);

            if (filters.updated_after && alertDate < new Date(filters.updated_after)) {
              continue;
            }

            if (filters.updated_before && alertDate > new Date(filters.updated_before)) {
              continue;
            }
          }

          const processedAlert: ProcessedAlert = {
            alert,
            cwes,
            repository: repo,
            organization: owner,
          };

          alerts.push(processedAlert);
        }

        // Check if we've reached the last page
        if (response.data.length < perPage) {
          break;
        }

        page++;
      } catch (error) {
        if ((error as any).status === 404) {
          logger.debug(`Repository ${owner}/${repo} not found or no code scanning enabled`);
          break;
        }

        logger.error(`Error fetching alerts for ${owner}/${repo}`, error as Error);
        throw error;
      }
    }

    logger.debug(`Fetched ${alerts.length} alerts for ${owner}/${repo}`);
    return alerts;
  }

  /**
   * Get all repositories for an organization
   */
  private async getOrganizationRepositories(org: string): Promise<string[]> {
    const repositories: string[] = [];
    let page = 1;
    const perPage = 100;

    while (true) {
      try {
        const response = await this.octokit.rest.repos.listForOrg({
          org,
          per_page: perPage,
          page,
          type: 'all',
        });

        if (response.data.length === 0) {
          break;
        }

        repositories.push(...response.data.map(repo => repo.name));

        if (response.data.length < perPage) {
          break;
        }

        page++;
      } catch (error) {
        logger.error(`Error fetching repositories for organization ${org}`, error as Error);
        throw error;
      }
    }

    return repositories;
  }

  /**
   * Get rate limit information
   */
  async getRateLimit(): Promise<{
    limit: number;
    remaining: number;
    reset: Date;
  }> {
    const response = await this.octokit.rest.rateLimit.get();

    return {
      limit: response.data.rate.limit,
      remaining: response.data.rate.remaining,
      reset: new Date(response.data.rate.reset * 1000),
    };
  }

  /**
   * Simple delay utility to avoid rate limiting
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Test the GitHub token and connectivity
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.octokit.rest.users.getAuthenticated();
      logger.info('GitHub API connection successful');
      return true;
    } catch (error) {
      logger.error('GitHub API connection failed', error as Error);
      return false;
    }
  }
}