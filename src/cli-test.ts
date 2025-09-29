#!/usr/bin/env node

/**
 * Simple test script to validate CLI functionality without requiring a real GitHub token
 */

import { parseCLIArguments } from './utils/cli';

console.log('🧪 Testing GHAS Reporting Engine CLI Interface\n');

// Test 1: Basic arguments
console.log('Test 1: Basic arguments');
try {
  const basicArgs = [
    'node', 'test.js',
    '--target', 'my-org',
    '--frameworks', 'owasp-top-10,sans-top-25',
    '--output', 'markdown'
  ];

  // Mock environment variable
  process.env.GITHUB_TOKEN = 'mock-token';

  const options = parseCLIArguments(basicArgs);
  console.log('✅ Parsed options:', {
    target: options.target,
    targetType: options.targetType,
    frameworks: options.frameworks,
    output: options.output,
    githubUrl: options.githubUrl,
    isAction: options.isAction
  });
} catch (error) {
  console.error('❌ Test 1 failed:', error);
}

// Test 2: Time period arguments
console.log('\nTest 2: Time period arguments');
try {
  const timeArgs = [
    'node', 'test.js',
    '--target', 'enterprise-org',
    '--target-type', 'enterprise',
    '--days', '30',
    '--output', 'html',
    '--verbose'
  ];

  const options = parseCLIArguments(timeArgs);
  console.log('✅ Parsed options:', {
    target: options.target,
    targetType: options.targetType,
    timePeriod: options.timePeriod,
    output: options.output,
    verbose: options.verbose
  });
} catch (error) {
  console.error('❌ Test 2 failed:', error);
}

// Test 3: Date range arguments  
console.log('\nTest 3: Date range arguments');
try {
  const dateArgs = [
    'node', 'test.js',
    '--target', 'test-org',
    '--start-date', '2024-01-01',
    '--end-date', '2024-12-31',
    '--frameworks', 'mitre-top-10-kev',
    '--output-file', './report.json',
    '--action'
  ];

  const options = parseCLIArguments(dateArgs);
  console.log('✅ Parsed options:', {
    target: options.target,
    timePeriod: options.timePeriod,
    frameworks: options.frameworks,
    outputFile: options.outputFile,
    isAction: options.isAction
  });
} catch (error) {
  console.error('❌ Test 3 failed:', error);
}

// Test 4: All frameworks
console.log('\nTest 4: All frameworks');
try {
  const allFrameworksArgs = [
    'node', 'test.js',
    '--target', 'security-org',
    '--frameworks', 'owasp-top-10,mitre-top-10-kev,sans-top-25',
    '--github-url', 'https://github.enterprise.com/api/v3'
  ];

  const options = parseCLIArguments(allFrameworksArgs);
  console.log('✅ Parsed options:', {
    target: options.target,
    frameworks: options.frameworks,
    githubUrl: options.githubUrl
  });
} catch (error) {
  console.error('❌ Test 4 failed:', error);
}

// Test 5: Error case - missing target
console.log('\nTest 5: Error handling - missing target');
try {
  const errorArgs = ['node', 'test.js', '--output', 'json'];
  const options = parseCLIArguments(errorArgs);
  console.error('❌ Test 5 should have failed but did not');
} catch (error) {
  console.log('✅ Correctly caught error:', (error as Error).message);
}

console.log('\n🎉 CLI interface tests completed!');

// Clean up
delete process.env.GITHUB_TOKEN;