import { GitHubClient } from './clients';
declare function initializeGitHubClient(token: string, githubUrl?: string): Promise<GitHubClient>;
declare function main(): Promise<void>;
export { initializeGitHubClient, main };
export * from './types';
export * from './clients';
export * from './utils';
//# sourceMappingURL=index.d.ts.map