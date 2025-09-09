import { describe, it, expect } from 'vitest';
import { CWEExtractor } from '../src/utils/CWEExtractor';
import { CodeQLAlert } from '../src/types';
import { mockCodeQLAlert } from './mockCodeQLAlert';

describe('CWEExtractor', () => {
  const mockAlert: CodeQLAlert = mockCodeQLAlert;


  it('should extract CWEs from rule tags', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-079');
  });

  it('should extract CWEs from rule description', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-089');
  });

  it('should extract CWEs from rule name', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-079');
  });

  it('should extract CWEs from classifications', () => {
    const cwes = CWEExtractor.extractCWEs(mockAlert);
    expect(cwes).toContain('CWE-022');
  });

  it('should remove duplicates', () => {
    const alertWithDuplicates: CodeQLAlert = {
      ...mockAlert,
      rule: {
        ...mockAlert.rule,
        name: 'CWE-079 Test',
        description: 'CWE-079 description'
      }
    };

    const cwes = CWEExtractor.extractCWEs(alertWithDuplicates);
    const cwe79Count = cwes.filter((cwe: string) => cwe === 'CWE-079').length;
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
    const cwes = ['CWE-079', 'CWE-089'];
    const formatted = CWEExtractor.formatCWEs(cwes);
    expect(formatted).toBe('CWE-079, CWE-089');
  });

  it('should extract CWE number', () => {
    const number = CWEExtractor.extractCWENumber('CWE-787');
    expect(number).toBe('787');
  });
});
