/**
 * Tests for GitHub client functionality
 * Note: These are mostly unit tests. Integration tests would require real GitHub API access.
 */

import { GitHubClient } from '../src/clients/github';
import { GitHubClientConfig, AlertTarget } from '../src/types';

// Mock the Octokit and related modules
jest.mock('@octokit/rest');
jest.mock('@octokit/auth-token');

describe('GitHubClient', () => {
  let client: GitHubClient;
  let mockConfig: GitHubClientConfig;

  beforeEach(() => {
    mockConfig = {
      token: 'test-token',
      baseUrl: 'https://api.github.com',
      userAgent: 'test-agent',
    };

    client = new GitHubClient(mockConfig);
  });

  describe('constructor', () => {
    it('should create a GitHubClient instance with proper configuration', () => {
      expect(client).toBeInstanceOf(GitHubClient);
    });

    it('should use default values for optional config parameters', () => {
      const minimalConfig: GitHubClientConfig = {
        token: 'test-token',
      };

      const minimalClient = new GitHubClient(minimalConfig);
      expect(minimalClient).toBeInstanceOf(GitHubClient);
    });
  });

  describe('fetchOrganizationAlerts', () => {
    it('should handle organization targets', async () => {
      const target: AlertTarget = {
        type: 'organization',
        name: 'test-org',
      };

      // Mock the private methods for testing
      const fetchOrgAlertsSpy = jest.spyOn(client as any, 'fetchOrgAlerts').mockResolvedValue([]);

      await client.fetchOrganizationAlerts(target);

      expect(fetchOrgAlertsSpy).toHaveBeenCalledWith(target, undefined);
    });

    it('should handle enterprise targets', async () => {
      const target: AlertTarget = {
        type: 'enterprise',
        name: 'test-enterprise',
      };

      // Mock the private methods for testing
      const fetchEnterpriseAlertsSpy = jest.spyOn(client as any, 'fetchEnterpriseAlerts').mockResolvedValue([]);

      await client.fetchOrganizationAlerts(target);

      expect(fetchEnterpriseAlertsSpy).toHaveBeenCalledWith(target, undefined);
    });
  });

  describe('testConnection', () => {
    it('should return true when connection is successful', async () => {
      // Mock successful connection
      const mockOctokit = {
        rest: {
          users: {
            getAuthenticated: jest.fn().mockResolvedValue({ data: { login: 'test-user' } }),
          },
        },
      };

      (client as any).octokit = mockOctokit;

      const result = await client.testConnection();
      expect(result).toBe(true);
    });

    it('should return false when connection fails', async () => {
      // Mock failed connection
      const mockOctokit = {
        rest: {
          users: {
            getAuthenticated: jest.fn().mockRejectedValue(new Error('Unauthorized')),
          },
        },
      };

      (client as any).octokit = mockOctokit;

      const result = await client.testConnection();
      expect(result).toBe(false);
    });
  });

  describe('getRateLimit', () => {
    it('should return formatted rate limit information', async () => {
      const mockResponse = {
        data: {
          rate: {
            limit: 5000,
            remaining: 4999,
            reset: 1640995200, // Unix timestamp
          },
        },
      };

      const mockOctokit = {
        rest: {
          rateLimit: {
            get: jest.fn().mockResolvedValue(mockResponse),
          },
        },
      };

      (client as any).octokit = mockOctokit;

      const rateLimit = await client.getRateLimit();

      expect(rateLimit).toEqual({
        limit: 5000,
        remaining: 4999,
        reset: new Date(1640995200 * 1000),
      });
    });
  });
});