#!/usr/bin/env node
/**
 * Quick validation script for pre-publish checks
 * Runs all critical tests before publishing to NPM
 */

const { execSync } = require('child_process');

console.log('🔍 Running Pre-Publish Validation...\n');

let exitCode = 0;

function run(command, description) {
  console.log(`\n📋 ${description}...`);
  try {
    const output = execSync(command, { encoding: 'utf8', stdio: 'inherit' });
    console.log(`✅ ${description} - PASSED`);
    return true;
  } catch (error) {
    console.error(`❌ ${description} - FAILED`);
    exitCode = 1;
    return false;
  }
}

// 1. Build check
run('npm run build', 'TypeScript Compilation');

// 2. Test suite
run('npm test', 'Serverless Compatibility Tests');

// 3. Import verification
run('npm run verify', 'Package Import Verification');

// 4. Smoke test - SQL injection detection
console.log('\n📋 Smoke Test - SQL Injection Detection...');
try {
  const { Aimless } = require('./dist/index.js');
  const aimless = new Aimless();
  const safe = aimless.isSafe("' OR 1=1--");
  if (safe) {
    throw new Error('Failed to detect SQL injection');
  }
  console.log('✅ Smoke Test - SQL Injection Detection - PASSED');
} catch (error) {
  console.error('❌ Smoke Test - SQL Injection Detection - FAILED');
  console.error('   Error:', error.message);
  exitCode = 1;
}

// 5. Smoke test - XSS detection
console.log('\n📋 Smoke Test - XSS Detection...');
try {
  const { Aimless } = require('./dist/index.js');
  const aimless = new Aimless();
  const safe = aimless.isSafe("<script>alert('xss')</script>");
  if (safe) {
    throw new Error('Failed to detect XSS');
  }
  console.log('✅ Smoke Test - XSS Detection - PASSED');
} catch (error) {
  console.error('❌ Smoke Test - XSS Detection - FAILED');
  console.error('   Error:', error.message);
  exitCode = 1;
}

// 6. Smoke test - Safe input
console.log('\n📋 Smoke Test - Safe Input Recognition...');
try {
  const { Aimless } = require('./dist/index.js');
  const aimless = new Aimless();
  const safe = aimless.isSafe("Hello, World!");
  if (!safe) {
    throw new Error('Safe input marked as unsafe');
  }
  console.log('✅ Smoke Test - Safe Input Recognition - PASSED');
} catch (error) {
  console.error('❌ Smoke Test - Safe Input Recognition - FAILED');
  console.error('   Error:', error.message);
  exitCode = 1;
}

// 7. File structure check
console.log('\n📋 File Structure Check...');
const fs = require('fs');
const requiredFiles = [
  'dist/index.js',
  'dist/index.d.ts',
  'dist/rasp/index.js',
  'dist/middleware/express.js',
  'README.md',
  'LICENSE',
  'package.json'
];

let structureOk = true;
for (const file of requiredFiles) {
  if (!fs.existsSync(file)) {
    console.error(`   ❌ Missing: ${file}`);
    structureOk = false;
    exitCode = 1;
  }
}
if (structureOk) {
  console.log('✅ File Structure Check - PASSED');
}

// 8. Version consistency check
console.log('\n📋 Version Consistency Check...');
try {
  const packageJson = require('./package.json');
  const version = packageJson.version;
  const readmeContent = fs.readFileSync('README.md', 'utf8');
  const changelogContent = fs.readFileSync('CHANGELOG.md', 'utf8');
  
  if (!readmeContent.includes(version)) {
    console.warn(`   ⚠️  Version ${version} not mentioned in README.md`);
  }
  if (!changelogContent.includes(version)) {
    console.warn(`   ⚠️  Version ${version} not in CHANGELOG.md`);
  }
  console.log(`✅ Version Consistency Check - PASSED (v${version})`);
} catch (error) {
  console.error('❌ Version Consistency Check - FAILED');
  console.error('   Error:', error.message);
  exitCode = 1;
}

// Final summary
console.log('\n' + '='.repeat(60));
if (exitCode === 0) {
  console.log('🎉 ALL VALIDATION CHECKS PASSED!');
  console.log('✅ Package is ready for publishing');
  console.log('\nTo publish, run: npm publish');
} else {
  console.log('❌ VALIDATION FAILED!');
  console.log('⚠️  Fix the issues above before publishing');
}
console.log('='.repeat(60) + '\n');

process.exit(exitCode);
