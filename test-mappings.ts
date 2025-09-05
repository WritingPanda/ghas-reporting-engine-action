import { OWASP_TOP_10_MAPPINGS } from './src/frameworks/mappings';
import { OWASPAnalyzer } from './src/frameworks/FrameworkAnalyzer';

console.log('🧪 Testing OWASP Mappings Structure...\n');

// Test 1: Verify mappings structure
console.log('📋 Testing mappings structure:');
for (const [category, info] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
  console.log(`  ${category}: ${info.name} (${info.cwes.length} CWEs)`);

  // Check first CWE in each category
  if (info.cwes.length > 0) {
    const firstCwe = info.cwes[0];
    console.log(`    First CWE: ${firstCwe.cwe} - ${firstCwe.name}`);
  }
}

// Test 2: Verify A03:2021 has expected CWEs
console.log('\n🎯 Testing A03:2021 Injection category:');
const injectionCategory = OWASP_TOP_10_MAPPINGS['A03:2021'];
const expectedCwes = ['CWE-89', 'CWE-79', 'CWE-113', 'CWE-77'];

expectedCwes.forEach(expectedCwe => {
  const found = injectionCategory.cwes.find(cwe => cwe.cwe === expectedCwe);
  if (found) {
    console.log(`  ✅ ${expectedCwe}: ${found.name}`);
  } else {
    console.log(`  ❌ ${expectedCwe}: NOT FOUND`);
  }
});

// Test 3: Test analyzer with mock alert
console.log('\n🔍 Testing OWASPAnalyzer:');
const analyzer = new OWASPAnalyzer();
console.log(`  Framework: ${analyzer.getFrameworkName()}`);

// Create a mock alert with SQL injection
const mockAlert = {
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

try {
  const mappings = analyzer.analyzeAlerts([mockAlert]);
  console.log(`  Generated ${mappings.length} mappings`);

  const injectionMapping = mappings.find(m => m.category.includes('A03:2021'));
  if (injectionMapping) {
    console.log(`  ✅ Found A03:2021 mapping with ${injectionMapping.alertCount} alert(s)`);
    console.log(`  CWEs in mapping: ${injectionMapping.cwes.slice(0, 5).join(', ')}...`);
  } else {
    console.log(`  ❌ A03:2021 mapping not found`);
  }
} catch (error) {
  console.log(`  ❌ Error testing analyzer: ${error}`);
}

console.log('\n✨ Test complete!');
