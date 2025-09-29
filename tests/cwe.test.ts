/**
 * Tests for CWE utility functions
 */

import { extractCWEsFromTags, extractUniqueCWEs, hasCWETags, isValidCWE } from '../src/utils/cwe';

describe('CWE Utilities', () => {
  describe('extractCWEsFromTags', () => {
    it('should extract CWE information from valid tags', () => {
      const tags = [
        'security',
        'external/cwe/cwe-089',
        'external/cwe/cwe-022',
        'maintainability'
      ];

      const cwes = extractCWEsFromTags(tags);

      expect(cwes).toHaveLength(2);
      expect(cwes[0]).toEqual({ id: 'CWE-89', number: 89 });
      expect(cwes[1]).toEqual({ id: 'CWE-22', number: 22 });
    });

    it('should handle empty tag arrays', () => {
      const cwes = extractCWEsFromTags([]);
      expect(cwes).toHaveLength(0);
    });

    it('should handle tags without CWE references', () => {
      const tags = ['security', 'maintainability', 'performance'];
      const cwes = extractCWEsFromTags(tags);
      expect(cwes).toHaveLength(0);
    });

    it('should handle malformed CWE tags', () => {
      const tags = [
        'external/cwe/invalid',
        'external/cwe/',
        'cwe-123', // Missing 'external/' prefix
        'external/cwe/cwe-abc' // Non-numeric CWE
      ];

      const cwes = extractCWEsFromTags(tags);
      expect(cwes).toHaveLength(0);
    });
  });

  describe('extractUniqueCWEs', () => {
    it('should extract unique CWE numbers from multiple tag collections', () => {
      const tagCollections = [
        ['security', 'external/cwe/cwe-089'],
        ['external/cwe/cwe-022', 'external/cwe/cwe-089'], // Duplicate CWE-89
        ['performance', 'external/cwe/cwe-476']
      ];

      const uniqueCWEs = extractUniqueCWEs(tagCollections);

      expect(uniqueCWEs).toEqual([22, 89, 476]); // Sorted and unique
    });

    it('should handle empty collections', () => {
      const uniqueCWEs = extractUniqueCWEs([]);
      expect(uniqueCWEs).toHaveLength(0);
    });
  });

  describe('hasCWETags', () => {
    it('should return true when CWE tags are present', () => {
      const tags = ['security', 'external/cwe/cwe-089'];
      expect(hasCWETags(tags)).toBe(true);
    });

    it('should return false when no CWE tags are present', () => {
      const tags = ['security', 'performance'];
      expect(hasCWETags(tags)).toBe(false);
    });

    it('should handle empty arrays', () => {
      expect(hasCWETags([])).toBe(false);
    });
  });

  describe('isValidCWE', () => {
    it('should validate positive integers as valid CWEs', () => {
      expect(isValidCWE(89)).toBe(true);
      expect(isValidCWE(1)).toBe(true);
      expect(isValidCWE(9999)).toBe(true);
    });

    it('should reject invalid CWE numbers', () => {
      expect(isValidCWE(0)).toBe(false);
      expect(isValidCWE(-1)).toBe(false);
      expect(isValidCWE(1.5)).toBe(false);
      expect(isValidCWE(NaN)).toBe(false);
      expect(isValidCWE(Infinity)).toBe(false);
    });
  });
});