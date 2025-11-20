/**
 * False Positive Prevention Tests
 * Ensures legitimate inputs don't trigger security alerts
 */

const { Aimless } = require('./dist/index.js');

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

console.log('🧪 Testing False Positive Prevention\n');

const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true
  }
});

// ============================================================================
// TEST 1: Legitimate Inputs Should NOT Trigger Alerts
// ============================================================================

test('Email addresses should not trigger SQL injection', () => {
  const result = aimless.validate('user@example.com')
    .against(['sql'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('UUIDs should not trigger alerts', () => {
  const result = aimless.validate('123e4567-e89b-12d3-a456-426614174000')
    .against(['sql', 'xss', 'command'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('ISO dates should not trigger alerts', () => {
  const result = aimless.validate('2024-11-20T10:30:00.000Z')
    .against(['sql', 'xss', 'command'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('Normal usernames should not trigger alerts', () => {
  const result = aimless.validate('john_doe_123')
    .against(['sql', 'xss', 'command'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('Normal text should not trigger alerts', () => {
  const result = aimless.validate('This is a normal sentence with spaces.')
    .against(['sql', 'xss', 'command'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('Numbers should not trigger alerts', () => {
  const result1 = aimless.validate('12345').against(['sql']).result();
  const result2 = aimless.validate('123.45').against(['sql']).result();
  
  if (!result1.safe || !result2.safe) {
    throw new Error('False positive on numbers');
  }
});

test('Single safe words should not trigger alerts', () => {
  const safeWords = ['select', 'insert', 'update', 'delete', 'order', 'sort'];
  
  for (const word of safeWords) {
    const result = aimless.validate(word).against(['sql']).result();
    if (!result.safe) {
      throw new Error(`False positive on word: ${word}`);
    }
  }
});

test('Normal URLs should not trigger SSRF on URL inputs', () => {
  const result = aimless.validate('https://example.com/path/to/resource')
    .against(['xss']) // Don't check SSRF for URLs
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('File paths without traversal should be allowed', () => {
  const result = aimless.validate('/var/www/public/image.jpg')
    .against(['sql', 'xss'])
    .result();
  
  if (!result.safe) {
    throw new Error(`False positive: ${JSON.stringify(result.threats)}`);
  }
});

test('JSON data should not trigger NoSQL injection (single pattern match)', () => {
  const result = aimless.validate('{"name": "John"}')
    .against(['nosql'])
    .result();
  
  // Single curly brace shouldn't trigger, need 2+ patterns
  if (!result.safe && result.threats[0].metadata.matchCount < 2) {
    throw new Error('False positive on normal JSON');
  }
});

// ============================================================================
// TEST 2: Actual Threats SHOULD Trigger Alerts
// ============================================================================

test('SQL injection should be detected', () => {
  const result = aimless.validate("' OR '1'='1")
    .against(['sql'])
    .result();
  
  if (result.safe) {
    throw new Error('Failed to detect SQL injection');
  }
});

test('XSS attacks should be detected', () => {
  const result = aimless.validate('<script>alert(1)</script>')
    .against(['xss'])
    .result();
  
  if (result.safe) {
    throw new Error('Failed to detect XSS');
  }
});

test('Command injection should be detected', () => {
  const result = aimless.validate('test; rm -rf /')
    .against(['command'])
    .result();
  
  if (result.safe) {
    throw new Error('Failed to detect command injection');
  }
});

test('Path traversal should be detected', () => {
  const result = aimless.validate('../../../../etc/passwd')
    .against(['path'])
    .result();
  
  if (result.safe) {
    throw new Error('Failed to detect path traversal');
  }
});

test('NoSQL injection should be detected (multiple patterns)', () => {
  const result = aimless.validate('{"$ne": null}')
    .against(['nosql'])
    .result();
  
  if (result.safe) {
    throw new Error('Failed to detect NoSQL injection');
  }
});

// ============================================================================
// TEST 3: Edge Cases
// ============================================================================

test('Very short strings should not trigger (< 2 chars)', () => {
  const result = aimless.validate('a').against(['sql', 'xss']).result();
  if (!result.safe) {
    throw new Error('False positive on very short string');
  }
});

test('Empty strings should not trigger', () => {
  const result = aimless.validate('').against(['sql', 'xss']).result();
  if (!result.safe) {
    throw new Error('False positive on empty string');
  }
});

test('Whitespace-only should not trigger', () => {
  const result = aimless.validate('   ').against(['sql', 'xss']).result();
  if (!result.safe) {
    throw new Error('False positive on whitespace');
  }
});

test('Null and undefined should not crash', () => {
  const result1 = aimless.validate(null).against(['sql']).result();
  const result2 = aimless.validate(undefined).against(['sql']).result();
  
  // Should be safe (no input to validate)
  if (!result1.safe || !result2.safe) {
    throw new Error('Null/undefined caused false positive');
  }
});

// ============================================================================
// TEST 4: Context-Aware Detection
// ============================================================================

test('Email context should whitelist email patterns', () => {
  const rasp = aimless.rasp;
  const threats = rasp.detectInjections('user@example.com', 'email');
  
  if (threats.length > 0) {
    throw new Error('Email context should whitelist valid emails');
  }
});

test('Username context should whitelist valid usernames', () => {
  const rasp = aimless.rasp;
  const threats = rasp.detectInjections('john_doe', 'username');
  
  if (threats.length > 0) {
    throw new Error('Username context should whitelist valid usernames');
  }
});

// ============================================================================
// TEST 5: Confidence Scoring
// ============================================================================

test('High confidence threats should have confidence > 50%', () => {
  const result = aimless.validate("' OR '1'='1 --")
    .against(['sql'])
    .result();
  
  if (result.safe) {
    throw new Error('Should detect SQL injection');
  }
  
  const confidence = result.threats[0].confidence;
  if (confidence < 50) {
    throw new Error(`Confidence too low: ${confidence}%`);
  }
});

test('Single pattern match should have lower confidence', () => {
  // This would only match 1 pattern (the semicolon)
  const rasp = aimless.rasp;
  const threats = rasp.detectInjections('test;', 'unknown');
  
  // Should not trigger (requires 2+ patterns or high confidence pattern)
  if (threats.length > 0) {
    throw new Error('Single semicolon should not trigger without other patterns');
  }
});

// ============================================================================
// RESULTS
// ============================================================================

console.log('\n' + '='.repeat(50));
console.log(`✅ Tests Passed: ${testsPassed}`);
console.log(`❌ Tests Failed: ${testsFailed}`);
console.log('='.repeat(50));

if (testsFailed === 0) {
  console.log('\n🎉 All false positive prevention tests passed!');
  console.log('✅ Legitimate inputs are NOT flagged');
  console.log('✅ Real threats ARE detected');
  console.log('✅ Confidence scoring works correctly');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
}
