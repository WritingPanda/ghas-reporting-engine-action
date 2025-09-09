import { describe, it, expect, beforeEach } from 'vitest';
import { ReportingEngine } from '../src/ReportingEngine';
import { Logger } from '../src/utils/Logger';

describe('ReportingEngine CWE Name Resolution', () => {
  let engine: ReportingEngine;

  beforeEach(() => {
    const logger = new Logger();
    engine = new ReportingEngine({
      token: 'dummy',
      organization: 'test',
      frameworks: ['owasp'],
      outputFormat: 'json',
      includeEmpty: false,
      logger
    });
  });

  it('should resolve CWE names from OWASP mappings', () => {
    // Test accessing the getCWEName method via reflection since it's private
    const getCWEName = (engine as any).getCWEName.bind(engine);

    // Test known CWEs from OWASP mappings
    expect(getCWEName('CWE-89')).toBe('Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)');
    expect(getCWEName('CWE-79')).toBe('Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)');
    expect(getCWEName('CWE-22')).toBe('Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)');
  });

  it('should handle CWEs with leading zeros', () => {
    const getCWEName = (engine as any).getCWEName.bind(engine);

    // Test CWEs with leading zeros should be normalized and found
    expect(getCWEName('CWE-089')).toBe('Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)');
    expect(getCWEName('CWE-079')).toBe('Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)');
    expect(getCWEName('CWE-022')).toBe('Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)');
  });

  it('should return Security Vulnerability for unknown CWEs', () => {
    const getCWEName = (engine as any).getCWEName.bind(engine);

    // Test unknown CWE
    expect(getCWEName('CWE-999999')).toBe('Security Vulnerability');
    expect(getCWEName('CWE-9999')).toBe('Security Vulnerability');
  });

  it('should handle case insensitive CWE format', () => {
    const getCWEName = (engine as any).getCWEName.bind(engine);

    // The normalization regex should handle case insensitive
    expect(getCWEName('cwe-089')).toBe('Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)');
    expect(getCWEName('cwe-079')).toBe('Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)');
  });

  it('should handle malformed CWE strings gracefully', () => {
    const getCWEName = (engine as any).getCWEName.bind(engine);

    // Test malformed inputs
    expect(getCWEName('')).toBe('Security Vulnerability');
    expect(getCWEName('invalid')).toBe('Security Vulnerability');
    expect(getCWEName('CWE-')).toBe('Security Vulnerability');
  });
});
