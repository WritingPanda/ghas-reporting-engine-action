/**
 * Demo script to test the GitHub client functionality
 * Run with: npm run demo
 */

import { GitHubClient } from './clients';
import { logger } from './utils';
import { AlertTarget } from './types';

async function demo(): Promise<void> {
  try {
    // Check for required environment variable
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      logger.error('GITHUB_TOKEN environment variable is required');
      logger.info('Please set your GitHub personal access token:');
      logger.info('export GITHUB_TOKEN=your_token_here');
      return;
    }

    logger.info('🚀 Starting GHAS Reporting Engine Demo');

    // Initialize the GitHub client
    const client = new GitHubClient({ token });

    // Test connection
    logger.info('🔍 Testing GitHub API connection...');
    const isConnected = await client.testConnection();

    if (!isConnected) {
      logger.error('❌ Failed to connect to GitHub API');
      return;
    }

    logger.info('✅ Successfully connected to GitHub API');

    // Check rate limits
    const rateLimit = await client.getRateLimit();
    logger.info('📊 GitHub API Rate Limit Status', {
      remaining: rateLimit.remaining,
      limit: rateLimit.limit,
      reset: rateLimit.reset.toISOString(),
      percentage: Math.round((rateLimit.remaining / rateLimit.limit) * 100),
    });

    logger.info('🎯 Demo completed successfully!');
    logger.info('');
    logger.info('Next steps:');
    logger.info('1. Replace "example-org" with a real organization name');
    logger.info('2. Uncomment the alert fetching code');
    logger.info('3. Run the demo to see CodeQL alerts with CWE mappings');

  } catch (error) {
    logger.error('❌ Demo failed', error as Error);
  }
}

// Add demo script to package.json if running directly
if (require.main === module) {
  demo().catch((error) => {
    logger.error('Unhandled error in demo', error);
    process.exit(1);
  });
}

export { demo };