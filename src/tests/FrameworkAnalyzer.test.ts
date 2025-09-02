import { describe, it, expect } from 'vitest';
import { OWASPAnalyzer, SANSAnalyzer, MITREKEVAnalyzer, FrameworkAnalyzerFactory } from '../frameworks/FrameworkAnalyzer';
import { CodeQLAlert } from '../types';

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
