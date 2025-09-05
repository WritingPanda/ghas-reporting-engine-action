import { CWEExtractor } from './src/utils/CWEExtractor';
import { OWASP_TOP_10_MAPPINGS } from './src/frameworks/mappings';

// Test CWE extraction format
const mockAlert = {
  rule: {
    name: 'SQL injection',
    id: 'js/sql-injection',
    description: 'Avoid SQL injection vulnerabilities (CWE-089)',
    tags: ['security', 'sql']
  },
  most_recent_instance: {
    classifications: ['CWE-089']
  }
} as any;

console.log('Testing CWE extraction...');
const extractedCWEs = CWEExtractor.extractCWEs(mockAlert);
console.log('Extracted CWEs:', extractedCWEs);

// Test lookup in OWASP mappings
console.log('\nTesting CWE lookup in OWASP mappings...');
extractedCWEs.forEach(cwe => {
  console.log(`Looking up: "${cwe}"`);

  let found = false;
  for (const category of Object.values(OWASP_TOP_10_MAPPINGS)) {
    for (const cweInfo of category.cwes) {
      if (cweInfo.cwe === cwe) {
        console.log(`✅ Found: ${cwe} -> ${cweInfo.name}`);
        found = true;
        break;
      }
    }
    if (found) break;
  }

  if (!found) {
    console.log(`❌ Not found: ${cwe}`);
    // Try to find similar CWEs
    for (const category of Object.values(OWASP_TOP_10_MAPPINGS)) {
      for (const cweInfo of category.cwes) {
        if (cweInfo.cwe.includes('89')) {
          console.log(`  Similar: ${cweInfo.cwe} -> ${cweInfo.name}`);
        }
      }
    }
  }
});
