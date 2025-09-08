import { describe, it, expect } from 'vitest';
import { OWASP_TOP_10_MAPPINGS } from '../src/frameworks/mappings';
import { mockCodeQLAlert } from './mockCodeQLAlert';
import { CodeQLAlert } from '../src/types';
import { CWEExtractor } from '../src/utils/CWEExtractor';

const mockAlert: CodeQLAlert = mockCodeQLAlert;

describe('OWASP Top 10 Mappings', () => {
  it('should have all 10 OWASP categories', () => {
    const categories = Object.keys(OWASP_TOP_10_MAPPINGS);
    expect(categories).toHaveLength(10);

    // Verify all expected categories exist
    expect(categories).toContain('A01:2021');
    expect(categories).toContain('A02:2021');
    expect(categories).toContain('A03:2021');
    expect(categories).toContain('A04:2021');
    expect(categories).toContain('A05:2021');
    expect(categories).toContain('A06:2021');
    expect(categories).toContain('A07:2021');
    expect(categories).toContain('A08:2021');
    expect(categories).toContain('A09:2021');
    expect(categories).toContain('A10:2021');
  });

  it('should have correct category names', () => {
    expect(OWASP_TOP_10_MAPPINGS['A01:2021'].name).toBe('Broken Access Control');
    expect(OWASP_TOP_10_MAPPINGS['A02:2021'].name).toBe('Cryptographic Failures');
    expect(OWASP_TOP_10_MAPPINGS['A03:2021'].name).toBe('Injection');
    expect(OWASP_TOP_10_MAPPINGS['A04:2021'].name).toBe('Insecure Design');
    expect(OWASP_TOP_10_MAPPINGS['A05:2021'].name).toBe('Security Misconfiguration');
    expect(OWASP_TOP_10_MAPPINGS['A06:2021'].name).toBe('Vulnerable and Outdated Components');
    expect(OWASP_TOP_10_MAPPINGS['A07:2021'].name).toBe('Identification and Authentication Failures');
    expect(OWASP_TOP_10_MAPPINGS['A08:2021'].name).toBe('Software and Data Integrity Failures');
    expect(OWASP_TOP_10_MAPPINGS['A09:2021'].name).toBe('Security Logging and Monitoring Failures');
    expect(OWASP_TOP_10_MAPPINGS['A10:2021'].name).toBe('Server-Side Request Forgery (SSRF)');
  });

  it('should have CWEs as objects with cwe and name properties', () => {
    for (const [category, info] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
      expect(Array.isArray(info.cwes)).toBe(true);
      expect(info.cwes.length).toBeGreaterThan(0);

      info.cwes.forEach(cweInfo => {
        expect(cweInfo).toHaveProperty('cwe');
        expect(cweInfo).toHaveProperty('name');
        expect(typeof cweInfo.cwe).toBe('string');
        expect(typeof cweInfo.name).toBe('string');
        expect(cweInfo.cwe).toMatch(/^CWE-\d+$/);
        expect(cweInfo.name.length).toBeGreaterThan(0);
      });
    }
  });

  it('should have specific CWEs in correct categories', () => {
    // Test A03:2021 Injection
    const injectionCwes = OWASP_TOP_10_MAPPINGS['A03:2021'].cwes;
    expect(injectionCwes.some(cwe => cwe.cwe === 'CWE-89')).toBe(true); // SQL Injection
    expect(injectionCwes.some(cwe => cwe.cwe === 'CWE-79')).toBe(true); // XSS
    expect(injectionCwes.some(cwe => cwe.cwe === 'CWE-113')).toBe(true); // HTTP Response Splitting

    // Test A01:2021 Broken Access Control
    const accessControlCwes = OWASP_TOP_10_MAPPINGS['A01:2021'].cwes;
    expect(accessControlCwes.some(cwe => cwe.cwe === 'CWE-22')).toBe(true); // Path Traversal
    expect(accessControlCwes.some(cwe => cwe.cwe === 'CWE-862')).toBe(true); // Missing Authorization

    // Test A10:2021 SSRF
    const ssrfCwes = OWASP_TOP_10_MAPPINGS['A10:2021'].cwes;
    expect(ssrfCwes.some(cwe => cwe.cwe === 'CWE-918')).toBe(true); // SSRF
  });

  it('should have correct CWE names for key vulnerabilities', () => {
    // Test SQL Injection name
    const injectionCwes = OWASP_TOP_10_MAPPINGS['A03:2021'].cwes;
    const sqlInjection = injectionCwes.find(cwe => cwe.cwe === 'CWE-89');
    expect(sqlInjection?.name).toBe('Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)');

    // Test XSS name
    const xss = injectionCwes.find(cwe => cwe.cwe === 'CWE-79');
    expect(xss?.name).toBe('Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)');

    // Test HTTP Response Splitting name
    const httpResponseSplitting = injectionCwes.find(cwe => cwe.cwe === 'CWE-113');
    expect(httpResponseSplitting?.name).toBe('Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)');

    // Test Path Traversal name
    const accessControlCwes = OWASP_TOP_10_MAPPINGS['A01:2021'].cwes;
    const pathTraversal = accessControlCwes.find(cwe => cwe.cwe === 'CWE-22');
    expect(pathTraversal?.name).toBe('Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)');
  });

  it('should not have duplicate CWEs within categories', () => {
    for (const [category, info] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
      const cweIds = info.cwes.map(cwe => cwe.cwe);
      const uniqueCweIds = new Set(cweIds);
      expect(cweIds.length).toBe(uniqueCweIds.size);
    }
  });

  it('should have reasonable number of CWEs per category', () => {
    for (const [category, info] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
      // Each category should have at least 1 CWE and not more than 50 (reasonable upper bound)
      expect(info.cwes.length).toBeGreaterThanOrEqual(1);
      expect(info.cwes.length).toBeLessThanOrEqual(50);
    }
  });

  it('should have A03:2021 Injection as one of the largest categories', () => {
    // A03:2021 Injection should have many CWEs since it covers various injection types
    const injectionCwes = OWASP_TOP_10_MAPPINGS['A03:2021'].cwes;
    expect(injectionCwes.length).toBeGreaterThan(20); // Should have many injection-related CWEs
  });

  it('should have A06:2021 as smallest category', () => {
    // A06:2021 Vulnerable and Outdated Components should have the fewest CWEs
    const vulnerableComponentsCwes = OWASP_TOP_10_MAPPINGS['A06:2021'].cwes;
    expect(vulnerableComponentsCwes.length).toBeLessThanOrEqual(5); // Should be a small category
  });

  it('should correctly match CWEs from mock CodeQL alert to OWASP categories', () => {
    // Extract CWEs from the mock alert
    const extractedCwes = CWEExtractor.extractCWEs(mockAlert);

    // Normalize CWE format (remove leading zeros for comparison)
    const normalizeCWE = (cwe: string): string => {
      const match = cwe.match(/CWE-(\d+)/);
      return match ? `CWE-${parseInt(match[1], 10)}` : cwe;
    };

    const normalizedCwes = extractedCwes.map(normalizeCWE);

    // The mock alert should contain these CWEs: CWE-22, CWE-79, CWE-89
    expect(normalizedCwes).toContain('CWE-22');
    expect(normalizedCwes).toContain('CWE-79');
    expect(normalizedCwes).toContain('CWE-89');

    // Function to find which OWASP category a CWE belongs to
    const findOwaspCategory = (cweId: string): string | null => {
      for (const [categoryId, categoryInfo] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
        if (categoryInfo.cwes.some(cwe => cwe.cwe === cweId)) {
          return categoryId;
        }
      }
      return null;
    };

    // Test that CWE-22 (Path Traversal) maps to A01:2021 (Broken Access Control)
    const cwe22Category = findOwaspCategory('CWE-22');
    expect(cwe22Category).toBe('A01:2021');
    expect(OWASP_TOP_10_MAPPINGS['A01:2021'].name).toBe('Broken Access Control');

    // Test that CWE-79 (XSS) maps to A03:2021 (Injection)
    const cwe79Category = findOwaspCategory('CWE-79');
    expect(cwe79Category).toBe('A03:2021');
    expect(OWASP_TOP_10_MAPPINGS['A03:2021'].name).toBe('Injection');

    // Test that CWE-89 (SQL Injection) maps to A03:2021 (Injection)
    const cwe89Category = findOwaspCategory('CWE-89');
    expect(cwe89Category).toBe('A03:2021');
    expect(OWASP_TOP_10_MAPPINGS['A03:2021'].name).toBe('Injection');

    // Verify that all extracted CWEs have corresponding OWASP mappings
    const mappedCategories = normalizedCwes.map(cwe => findOwaspCategory(cwe)).filter(Boolean);
    expect(mappedCategories.length).toBe(3); // All 3 CWEs should be mapped

    // Verify that we get both A01:2021 and A03:2021 categories
    const uniqueCategories = [...new Set(mappedCategories)];
    expect(uniqueCategories).toContain('A01:2021');
    expect(uniqueCategories).toContain('A03:2021');
    expect(uniqueCategories.length).toBe(2); // Should map to exactly 2 categories
  });
});
