import { OWASP_TOP_10_MAPPINGS } from './src/frameworks/mappings';

// Test the OWASP mappings structure
console.log('Testing OWASP mappings structure...');

// Get the keys and check first category
const owaspKeys = Object.keys(OWASP_TOP_10_MAPPINGS);
const firstKey = owaspKeys[0];
const firstCategory = OWASP_TOP_10_MAPPINGS[firstKey as keyof typeof OWASP_TOP_10_MAPPINGS];

console.log('First OWASP category:', firstKey);
console.log('Category name:', firstCategory.name);
console.log('Has cwes array:', Array.isArray(firstCategory.cwes));
console.log('First CWE in category:', firstCategory.cwes[0]);

// Check if all categories have the new structure
let allValid = true;
Object.entries(OWASP_TOP_10_MAPPINGS).forEach(([categoryId, category]) => {
  if (!Array.isArray(category.cwes)) {
    console.error(`❌ Category ${categoryId} missing cwes array`);
    allValid = false;
    return;
  }

  category.cwes.forEach((cweInfo, cweIndex) => {
    if (typeof cweInfo !== 'object' || !cweInfo.cwe || !cweInfo.name) {
      console.error(`❌ Category ${categoryId}, CWE ${cweIndex} has invalid structure:`, cweInfo);
      allValid = false;
    }
  });
});

// Test CWE lookup functionality
const testCWEs = ['CWE-89', 'CWE-79', 'CWE-22'];
console.log('\nTesting CWE lookup...');

testCWEs.forEach(targetCWE => {
  let found = false;
  let foundName = '';
  let foundCategory = '';

  for (const [categoryId, category] of Object.entries(OWASP_TOP_10_MAPPINGS)) {
    for (const cweInfo of category.cwes) {
      if (cweInfo.cwe === targetCWE) {
        found = true;
        foundName = cweInfo.name;
        foundCategory = categoryId;
        break;
      }
    }
    if (found) break;
  }

  if (found) {
    console.log(`✅ ${targetCWE}: ${foundName} (in ${foundCategory})`);
  } else {
    console.log(`❌ ${targetCWE}: Not found`);
  }
});

console.log(`\nFound ${owaspKeys.length} OWASP categories:`);
owaspKeys.forEach(key => {
  const category = OWASP_TOP_10_MAPPINGS[key as keyof typeof OWASP_TOP_10_MAPPINGS];
  console.log(`  ${key}: ${category.name} (${category.cwes.length} CWEs)`);
});

if (allValid) {
  console.log('\n✅ All OWASP mappings have correct structure');
} else {
  console.log('\n❌ Some OWASP mappings have invalid structure');
}
