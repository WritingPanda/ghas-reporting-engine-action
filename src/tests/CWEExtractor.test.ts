import { describe, it, expect } from 'vitest';
import { CWEExtractor } from '../utils/CWEExtractor';
import { CodeQLAlert } from '../types';

describe('CWEExtractor', () => {
  const mockAlert: CodeQLAlert = {
    number: 1,
    rule: {
      id: 'test-rule',
      name: 'Test Rule with CWE-79',
      description: 'This rule detects CWE-89 issues',
      tags: ['external/cwe/cwe-79', 'security']
    },
    tool: {
      name: 'CodeQL'
    },
    most_recent_instance: {
      ref: 'main',
      analysis_key: 'test',
      environment: 'default',
      category: 'security',
      state: 'open',
      commit_sha: 'abc123',
      message: { text: 'Test message' },
      location: {
        path: 'test.js',
        start_line: 1,
        end_line: 1,
        start_column: 1,
        end_column: 10
      },
      classifications: ['CWE-22']
    },
    state: 'open',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    url: 'https://api.github.com/repos/test/test/code-scanning/alerts/1',
    html_url: 'https://github.com/test/test/security/code-scanning/1',
    instances_url: 'https://api.github.com/repos/test/test/code-scanning/alerts/1/instances'
  };

  it('should extract CWEs from rule tags', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-79');
  });

  it('should extract CWEs from rule description', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-89');
  });

  it('should extract CWEs from rule name', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-79');
  });

  it('should extract CWEs from classifications', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-22');
  });

  it('should remove duplicates', () => {
    const alertWithDuplicates: CodeQLAlert = {
      ...mockAlert,
      rule: {
        ...mockAlert.rule,
        name: 'CWE-79 Test',
        description: 'CWE-79 description'
      }
    };

    const cwes = CWEExtractor.extractCWEs(alertWithDuplicates);
    const cwe79Count = cwes.filter((cwe: string) => cwe === 'CWE-79').length;
    expect(cwe79Count).toBe(1);
  });

  it('should return empty array for alert with no CWEs', () => {
    const alertNoCWE: CodeQLAlert = {
      ...mockAlert,
      rule: {
        id: 'test',
        name: 'Test Rule',
        description: 'No CWE here'
      },
      most_recent_instance: {
        ...mockAlert.most_recent_instance,
        classifications: []
      }
    };

    const cwes = CWEExtractor.extractCWEs(alertNoCWE);
    expect(cwes).toHaveLength(0);
  });

  it('should check if alert has CWE mapping', () => {
    expect(CWEExtractor.hasCWEMapping(mockAlert)).toBe(true);
  });

  it('should format CWEs as string', () => {
    const cwes = ['CWE-79', 'CWE-89'];
    const formatted = CWEExtractor.formatCWEs(cwes);
    expect(formatted).toBe('CWE-79, CWE-89');
  });

  it('should extract CWE number', () => {
    const number = CWEExtractor.extractCWENumber('CWE-787');
    expect(number).toBe('787');
  });
});
