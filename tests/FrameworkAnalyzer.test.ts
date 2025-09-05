import { describe, it, expect } from 'vitest';
import { OWASPAnalyzer, SANSAnalyzer, MITREKEVAnalyzer, FrameworkAnalyzerFactory } from '../src/frameworks/FrameworkAnalyzer';
import { CodeQLAlert } from '../src/types';

describe('FrameworkAnalyzers', () => {
  const mockAlert: CodeQLAlert = {
    number: 1,
    rule: {
      id: 'test-rule',
      name: 'SQL Injection Test',
      description: 'Detects SQL injection vulnerabilities',
      tags: ['external/cwe/cwe-89']
    },
    tool: { name: 'CodeQL' },
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
      }
    },
    state: 'open',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    url: 'https://api.github.com/test',
    html_url: 'https://github.com/test',
    instances_url: 'https://api.github.com/test/instances'
  };

  describe('OWASPAnalyzer', () => {
    it('should create OWASP analyzer', () => {
      const analyzer = new OWASPAnalyzer();
      expect(analyzer.getFrameworkName()).toBe('OWASP Top 10 2021');
    });

    it('should map SQL injection to A03:2021 Injection', () => {
      const analyzer = new OWASPAnalyzer();
      const mappings = analyzer.analyzeAlerts([mockAlert]);

      const injectionMapping = mappings.find(m => m.category.includes('A03:2021'));
      expect(injectionMapping).toBeDefined();
      expect(injectionMapping?.alertCount).toBe(1);
      expect(injectionMapping?.cwes).toContain('CWE-89');
    });

    it('should handle multiple CWEs in different categories', () => {
      const analyzer = new OWASPAnalyzer();

      // Create alerts for different OWASP categories
      const xssAlert: CodeQLAlert = {
        ...mockAlert,
        number: 2,
        rule: {
          ...mockAlert.rule,
          name: 'XSS Test',
          description: 'Cross-site scripting vulnerability',
          tags: ['external/cwe/cwe-79']
        }
      };

      const accessControlAlert: CodeQLAlert = {
        ...mockAlert,
        number: 3,
        rule: {
          ...mockAlert.rule,
          name: 'Path Traversal Test',
          description: 'Path traversal vulnerability',
          tags: ['external/cwe/cwe-22']
        }
      };

      const mappings = analyzer.analyzeAlerts([mockAlert, xssAlert, accessControlAlert]);

      // Check A03:2021 Injection (should have 2 alerts: SQL injection + XSS)
      const injectionMapping = mappings.find(m => m.category.includes('A03:2021'));
      expect(injectionMapping).toBeDefined();
      expect(injectionMapping?.alertCount).toBe(2);
      expect(injectionMapping?.cwes).toContain('CWE-89');
      expect(injectionMapping?.cwes).toContain('CWE-79');

      // Check A01:2021 Broken Access Control (should have 1 alert: path traversal)
      const accessControlMapping = mappings.find(m => m.category.includes('A01:2021'));
      expect(accessControlMapping).toBeDefined();
      expect(accessControlMapping?.alertCount).toBe(1);
      expect(accessControlMapping?.cwes).toContain('CWE-22');
    });

    it('should return empty mappings for unmatched CWEs', () => {
      const analyzer = new OWASPAnalyzer();

      const unmatchedAlert: CodeQLAlert = {
        ...mockAlert,
        rule: {
          ...mockAlert.rule,
          name: 'Unmatched CWE Test',
          description: 'This should not match any OWASP category',
          tags: ['external/cwe/cwe-9999'] // Non-existent CWE
        }
      };

      const mappings = analyzer.analyzeAlerts([unmatchedAlert]);

      // All mappings should have 0 alerts
      mappings.forEach(mapping => {
        expect(mapping.alertCount).toBe(0);
      });
    });

    it('should extract CWE names correctly from new mappings structure', () => {
      const analyzer = new OWASPAnalyzer();
      const mappings = analyzer.analyzeAlerts([]);

      // Find the A03:2021 mapping and verify it contains the expected CWEs
      const injectionMapping = mappings.find(m => m.category.includes('A03:2021'));
      expect(injectionMapping).toBeDefined();
      expect(injectionMapping?.cwes).toContain('CWE-89'); // SQL Injection
      expect(injectionMapping?.cwes).toContain('CWE-79'); // XSS
      expect(injectionMapping?.cwes).toContain('CWE-113'); // HTTP Response Splitting
      expect(injectionMapping?.cwes).toContain('CWE-77'); // Command Injection

      // Verify CWEs are strings, not objects
      injectionMapping?.cwes.forEach(cwe => {
        expect(typeof cwe).toBe('string');
        expect(cwe).toMatch(/^CWE-\d+$/);
      });
    });

    it('should sort mappings by alert count descending', () => {
      const analyzer = new OWASPAnalyzer();

      // Create multiple alerts for different categories
      const alerts = [
        mockAlert, // CWE-89 -> A03:2021
        { ...mockAlert, number: 2, rule: { ...mockAlert.rule, tags: ['external/cwe/cwe-79'] } }, // CWE-79 -> A03:2021
        { ...mockAlert, number: 3, rule: { ...mockAlert.rule, tags: ['external/cwe/cwe-22'] } }, // CWE-22 -> A01:2021
      ];

      const mappings = analyzer.analyzeAlerts(alerts);

      // A03:2021 should be first (2 alerts), A01:2021 should be second (1 alert)
      expect(mappings[0].category).toContain('A03:2021');
      expect(mappings[0].alertCount).toBe(2);

      const accessControlIndex = mappings.findIndex(m => m.category.includes('A01:2021'));
      expect(accessControlIndex).toBeGreaterThan(0);
      expect(mappings[accessControlIndex].alertCount).toBe(1);
    });
  });

  describe('SANSAnalyzer', () => {
    it('should create SANS analyzer', () => {
      const analyzer = new SANSAnalyzer();
      expect(analyzer.getFrameworkName()).toBe('SANS Top 25');
    });

    it('should map SQL injection to rank 3', () => {
      const analyzer = new SANSAnalyzer();
      const mappings = analyzer.analyzeAlerts([mockAlert]);

      const sqlMapping = mappings.find(m => m.rank === 3);
      expect(sqlMapping).toBeDefined();
      expect(sqlMapping?.alertCount).toBe(1);
      expect(sqlMapping?.cwes).toContain('CWE-89');
    });

    it('should sort by rank', () => {
      const analyzer = new SANSAnalyzer();
      const mappings = analyzer.analyzeAlerts([mockAlert]);

      for (let i = 1; i < mappings.length; i++) {
        const current = mappings[i].rank || 0;
        const previous = mappings[i - 1].rank || 0;
        expect(current).toBeGreaterThanOrEqual(previous);
      }
    });
  });

  describe('MITREKEVAnalyzer', () => {
    it('should create MITRE KEV analyzer', () => {
      const analyzer = new MITREKEVAnalyzer();
      expect(analyzer.getFrameworkName()).toBe('MITRE Top 10 KEV');
    });

    it('should map SQL injection to rank 8', () => {
      const analyzer = new MITREKEVAnalyzer();
      const mappings = analyzer.analyzeAlerts([mockAlert]);

      const sqlMapping = mappings.find(m => m.rank === 8);
      expect(sqlMapping).toBeDefined();
      expect(sqlMapping?.alertCount).toBe(1);
      expect(sqlMapping?.cwes).toContain('CWE-89');
    });
  });

  describe('FrameworkAnalyzerFactory', () => {
    it('should create OWASP analyzer', () => {
      const analyzer = FrameworkAnalyzerFactory.createAnalyzer('owasp');
      expect(analyzer).toBeInstanceOf(OWASPAnalyzer);
    });

    it('should create SANS analyzer', () => {
      const analyzer = FrameworkAnalyzerFactory.createAnalyzer('sans');
      expect(analyzer).toBeInstanceOf(SANSAnalyzer);
    });

    it('should create MITRE KEV analyzer', () => {
      const analyzer1 = FrameworkAnalyzerFactory.createAnalyzer('kev');
      const analyzer2 = FrameworkAnalyzerFactory.createAnalyzer('mitre');
      expect(analyzer1).toBeInstanceOf(MITREKEVAnalyzer);
      expect(analyzer2).toBeInstanceOf(MITREKEVAnalyzer);
    });

    it('should throw error for unsupported framework', () => {
      expect(() => {
        FrameworkAnalyzerFactory.createAnalyzer('unsupported');
      }).toThrow('Unsupported framework: unsupported');
    });

    it('should return supported frameworks', () => {
      const frameworks = FrameworkAnalyzerFactory.getSupportedFrameworks();
      expect(frameworks).toEqual(['owasp', 'sans', 'kev']);
    });
  });
});
