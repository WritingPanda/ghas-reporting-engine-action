import { CodeQLAlert } from '../src/types';

export const mockCodeQLAlert: CodeQLAlert = {
  number: 4,
  created_at: "2020-02-13T12:29:18Z",
  url: "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/4",
  html_url: "https://github.com/octocat/hello-world/code-scanning/4",
  state: "open",
  dismissed_by: "null",
  dismissed_at: "null",
  dismissed_reason: "null",
  dismissed_comment: "null",
  rule: {
    id: "js/zipslip",
    severity: "error",
    tags: [
      "security",
      "external/cwe/cwe-022",
      "external/cwe/cwe-079",
      "external/cwe/cwe-089"
    ],
    description: "Arbitrary file write during zip extraction",
    name: "js/zipslip"
  },
  tool: {
    name: "CodeQL",
    version: "2.4.0"
  },
  most_recent_instance: {
    ref: "refs/heads/main",
    analysis_key: ".github/workflows/codeql-analysis.yml:CodeQL-Build",
    category: ".github/workflows/codeql-analysis.yml:CodeQL-Build",
    environment: "{}",
    state: "open",
    commit_sha: "39406e42cb832f683daa691dd652a8dc36ee8930",
    message: {
      text: "This path depends on a user-provided value."
    },
    location: {
      path: "spec-main/api-session-spec.ts",
      start_line: 917,
      end_line: 917,
      start_column: 7,
      end_column: 18
    },
    classifications: [
      "test"
    ]
  },
  instances_url: "https://api.github.com/repos/octocat/hello-world/code-scanning/alerts/4/instances",
  repository: {
    name: "Hello-World",
    full_name: "octocat/Hello-World",
    owner: {
      login: "octocat"
    },
  },
  updated_at: '2024-01-01T00:00:00Z'
};