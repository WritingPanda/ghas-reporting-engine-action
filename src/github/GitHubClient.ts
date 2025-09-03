import { Octokit } from 'octokit';
import { CodeQLAlert, Repository } from '../types';
import { Logger } from '../utils/Logger';

/**
 * GitHub API client for fetching CodeQL alerts and repository information
 */
export class GitHubClient {
  private octokit: Octokit;
  private logger: Logger;

  constructor(token: string, logger: Logger) {
    this.octokit = new Octokit({ auth: token });
    this.logger = logger;
  }

  /**
   * Get all repositories for an organization
   */
  async getOrganizationRepositories(org: string, type: 'all' | 'public' | 'private' = 'all'): Promise<Repository[]> {
    this.logger.info(`Fetching repositories for organization: ${org}`);

    try {
      const repositories: Repository[] = [];
      let page = 1;
      const perPage = 100;

      while (true) {
        const response = await this.octokit.rest.repos.listForOrg({
          org,
          type,
          per_page: perPage,
          page,
          sort: 'updated',
          direction: 'desc'
        });

        if (response.data.length === 0) break;

        repositories.push(...response.data as Repository[]);

        if (response.data.length < perPage) break;
        page++;
      }

      this.logger.info(`Found ${repositories.length} repositories for organization ${org}`);
      return repositories;
    } catch (error) {
      this.logger.error(`Failed to fetch repositories for organization ${org}: ${error}`);
      throw error;
    }
  }

  /**
   * Get all repositories for an enterprise (requires enterprise permissions)
   */
  async getEnterpriseRepositories(enterprise: string): Promise<Repository[]> {
    this.logger.info(`Fetching repositories for enterprise: ${enterprise}`);

    try {
      // Note: This requires enterprise admin permissions
      // For now, we'll get organizations in the enterprise and then their repos
      const orgs = await this.getEnterpriseOrganizations(enterprise);
      const allRepos: Repository[] = [];

      for (const org of orgs) {
        const repos = await this.getOrganizationRepositories(org.login);
        allRepos.push(...repos);
      }

      this.logger.info(`Found ${allRepos.length} repositories across ${orgs.length} organizations in enterprise ${enterprise}`);
      return allRepos;
    } catch (error) {
      this.logger.error(`Failed to fetch repositories for enterprise ${enterprise}: ${error}`);
      throw error;
    }
  }

  /**
   * Get organizations in an enterprise
   */
  private async getEnterpriseOrganizations(enterprise: string): Promise<any[]> {
    try {
      const response = await this.octokit.request('GET /enterprises/{enterprise}/organizations', {
        enterprise
      });
      return response.data;
    } catch (error) {
      this.logger.error(`Failed to fetch organizations for enterprise ${enterprise}: ${error}`);
      throw error;
    }
  }

  /**
   * Get CodeQL alerts for a repository
   */
  async getCodeQLAlerts(
    owner: string,
    repo: string,
    state: 'open' | 'dismissed' | 'fixed' = 'open',
    severity?: string
  ): Promise<CodeQLAlert[]> {
    this.logger.debug(`Fetching CodeQL alerts for ${owner}/${repo}`);

    try {
      const alerts: CodeQLAlert[] = [];
      let page = 1;
      const perPage = 100;

      while (true) {
        const response = await this.octokit.rest.codeScanning.listAlertsForRepo({
          owner,
          repo,
          state,
          per_page: perPage,
          page,
          severity
        });

        if (response.data.length === 0) break;

        // Add repository information to each alert
        const alertsWithRepo = response.data.map((alert: any) => ({
          ...alert,
          repository: {
            name: repo,
            full_name: `${owner}/${repo}`,
            owner: { login: owner }
          }
        }));

        alerts.push(...alertsWithRepo);

        if (response.data.length < perPage) break;
        page++;
      }

      this.logger.debug(`Found ${alerts.length} CodeQL alerts for ${owner}/${repo}`);
      return alerts;
    } catch (error) {
      // Log but don't throw for individual repo failures
      this.logger.warn(`Failed to fetch CodeQL alerts for ${owner}/${repo}: ${error}`);
      return [];
    }
  }

  /**
   * Get CodeQL alerts for multiple repositories
   */
  async getCodeQLAlertsForRepositories(
    repositories: Repository[],
    state: 'open' | 'dismissed' | 'fixed' = 'open',
    severity?: string
  ): Promise<CodeQLAlert[]> {
    this.logger.info(`Fetching CodeQL alerts for ${repositories.length} repositories`);

    const allAlerts: CodeQLAlert[] = [];
    const batchSize = 5; // Process repos in batches to avoid rate limiting

    for (let i = 0; i < repositories.length; i += batchSize) {
      const batch = repositories.slice(i, i + batchSize);

      const batchPromises = batch.map(repo =>
        this.getCodeQLAlerts(repo.owner.login, repo.name, state, severity)
      );

      const batchResults = await Promise.all(batchPromises);

      for (const alerts of batchResults) {
        allAlerts.push(...alerts);
      }

      // Small delay between batches to be respectful to the API
      if (i + batchSize < repositories.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    this.logger.info(`Found ${allAlerts.length} total CodeQL alerts across all repositories`);
    return allAlerts;
  }

  /**
   * Check if a repository has Advanced Security enabled
   */
  async hasAdvancedSecurityEnabled(owner: string, repo: string): Promise<boolean> {
    try {
      const response = await this.octokit.rest.repos.get({
        owner,
        repo
      });

      return response.data.security_and_analysis?.advanced_security?.status === 'enabled';

    } catch (error) {
      this.logger.warn(`Could not check Advanced Security status for ${owner}/${repo}: ${error}`);
      return false;
    }
  }

  /**
   * Filter repositories that have Advanced Security enabled
   */
  async filterRepositoriesWithAdvancedSecurity(repositories: Repository[]): Promise<Repository[]> {
    this.logger.info('Filtering repositories with Advanced Security enabled...');

    const enabledRepos: Repository[] = [];

    for (const repo of repositories) {
      const hasGHAS = await this.hasAdvancedSecurityEnabled(repo.owner.login, repo.name);
      if (hasGHAS) {
        enabledRepos.push(repo);
      }
    }

    this.logger.info(`${enabledRepos.length} out of ${repositories.length} repositories have Advanced Security enabled`);
    return enabledRepos;
  }
}
