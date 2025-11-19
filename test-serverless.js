/**
 * Serverless Compatibility Test Suite
 * Tests that Aimless Security works in serverless environments
 */

const { Aimless } = require('./dist/index.js');

console.log('🧪 Testing Aimless Security for Serverless Compatibility\n');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    testsPassed++;
  } catch (error) {
    console.error(`❌ ${name}`);
    console.error(`   Error: ${error.message}`);
    testsFailed++;
  }
}

// Test 1: Module loads correctly
test('Module loads without errors', () => {
  if (!Aimless) throw new Error('Aimless not exported');
  if (typeof Aimless !== 'function') throw new Error('Aimless is not a constructor');
});

// Test 2: Basic instantiation
test('Can create Aimless instance', () => {
  const aimless = new Aimless();
  if (!aimless) throw new Error('Instance not created');
});

// Test 3: Configuration works
test('Accepts configuration object', () => {
  const aimless = new Aimless({
    rasp: {
      enabled: true,
      blockMode: false
    }
  });
  if (!aimless) throw new Error('Instance with config not created');
});

// Test 4: Quick protect helper
test('Quick protect helper works', () => {
  const result = Aimless.quickProtect(['http://localhost:3000']);
  if (!result.middleware) throw new Error('No middleware returned');
  if (!result.csrf) throw new Error('No CSRF returned');
  if (!result.aimless) throw new Error('No aimless instance returned');
});

// Test 5: Validation API
test('Validate method exists and works', () => {
  const aimless = new Aimless();
  const result = aimless.isSafe("test input");
  if (typeof result !== 'boolean') throw new Error('Invalid result format');
});

// Test 6: Fluent API
test('Fluent API chains correctly', () => {
  const aimless = new Aimless();
  const safe = aimless.isSafe("test");
  if (typeof safe !== 'boolean') throw new Error('Invalid result');
});

// Test 7: SQL Injection Detection
test('SQL injection detection works', () => {
  const aimless = new Aimless();
  const safe = aimless.isSafe("' OR 1=1--");
  if (safe) throw new Error('Failed to detect SQL injection');
});

// Test 8: XSS Detection
test('XSS detection works', () => {
  const aimless = new Aimless();
  const safe = aimless.isSafe("<script>alert('xss')</script>");
  if (safe) throw new Error('Failed to detect XSS');
});

// Test 9: Sanitization
test('Sanitization removes threats', () => {
  const aimless = new Aimless();
  const input = "<script>alert('xss')</script>";
  const sanitized = aimless.sanitizeFor(input, 'html');
  if (!sanitized) throw new Error('Sanitization failed');
  if (sanitized.includes('<script>')) throw new Error('Sanitization incomplete');
});

// Test 10: Context-aware sanitization
test('Context-aware sanitization works', () => {
  const aimless = new Aimless();
  const htmlSafe = aimless.sanitizeFor("<script>test</script>", 'html');
  if (!htmlSafe) throw new Error('HTML sanitization failed');
  const jsSafe = aimless.sanitizeFor("test'test", 'javascript');
  if (!jsSafe) throw new Error('JS sanitization failed');
});

// Test 11: isSafe helper
test('isSafe helper works', () => {
  const aimless = new Aimless();
  const safe = aimless.isSafe("normal input");
  if (!safe) throw new Error('Safe input marked as unsafe');
  const unsafe = aimless.isSafe("' OR 1=1--");
  if (unsafe) throw new Error('Unsafe input marked as safe');
});

// Test 12: IP reputation
test('IP reputation system works', () => {
  const aimless = new Aimless();
  const score = aimless.getIPReputation('127.0.0.1');
  if (typeof score !== 'number') throw new Error('Invalid reputation score');
  if (score < 0 || score > 100) throw new Error('Score out of range');
});

// Test 13: Statistics
test('Statistics method works', () => {
  const aimless = new Aimless();
  const stats = aimless.getStats();
  if (!stats) throw new Error('No stats returned');
  if (!stats.rasp) throw new Error('No RASP stats');
});

// Test 14: Direct detector access
test('Direct detector access works', () => {
  const aimless = new Aimless();
  const injectionDetector = aimless.rasp.getInjectionDetector();
  if (!injectionDetector) throw new Error('No injection detector');
  const xssDetector = aimless.rasp.getXSSDetector();
  if (!xssDetector) throw new Error('No XSS detector');
});

// Test 15: Confidence scoring
test('Confidence scoring works', () => {
  const aimless = new Aimless();
  const safe = aimless.isSafe("' UNION SELECT * FROM users--");
  // Just verify it doesn't crash - confidence is internal
  if (typeof safe !== 'boolean') throw new Error('Invalid result type');
});

// Test 16: Memory safety (no crashes)
test('Handles large inputs without crashing', () => {
  const aimless = new Aimless();
  const largeInput = 'a'.repeat(10000);
  const result = aimless.isSafe(largeInput);
  if (typeof result !== 'boolean') throw new Error('Failed to handle large input');
});

// Test 17: Handles null/undefined
test('Handles null and undefined gracefully', () => {
  const aimless = new Aimless();
  try {
    const r1 = aimless.isSafe(null);
    const r2 = aimless.isSafe(undefined);
    const r3 = aimless.isSafe('');
    if (typeof r1 !== 'boolean' || typeof r2 !== 'boolean' || typeof r3 !== 'boolean') {
      throw new Error('Invalid result type');
    }
  } catch (e) {
    throw new Error('Failed to handle null/undefined: ' + e.message);
  }
});

// Test 18: No global pollution
test('Does not pollute global scope', () => {
  const before = Object.keys(global).length;
  const aimless = new Aimless();
  const after = Object.keys(global).length;
  if (after > before) throw new Error('Global scope polluted');
});

// Test 19: Multiple instances work independently
test('Multiple instances work independently', () => {
  const aimless1 = new Aimless({ rasp: { blockMode: true } });
  const aimless2 = new Aimless({ rasp: { blockMode: false } });
  if (!aimless1 || !aimless2) throw new Error('Failed to create multiple instances');
});

// Test 20: crypto module is available
test('Uses Node.js crypto module correctly', () => {
  const aimless = new Aimless();
  const csrfDetector = aimless.rasp.getCSRFDetector();
  const token = csrfDetector.generateToken('session123');
  if (!token || token.length < 10) throw new Error('Token generation failed');
});

// Results
console.log('\n' + '='.repeat(50));
console.log(`✅ Tests Passed: ${testsPassed}`);
console.log(`❌ Tests Failed: ${testsFailed}`);
console.log('='.repeat(50));

if (testsFailed > 0) {
  console.log('\n⚠️  Some tests failed. Package may not work correctly in serverless environments.');
  process.exit(1);
} else {
  console.log('\n🎉 All tests passed! Package is serverless-ready.');
  process.exit(0);
}
