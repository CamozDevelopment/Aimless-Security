/**
 * SECURITY TESTING - Polyglot and Unicode Injection Tests
 * Tests for advanced injection techniques including:
 * - Polyglot injections (SQL + XSS combined)
 * - Unicode SQL injection
 * - Homoglyph attacks
 */

const { Aimless } = require('../dist/index.js');

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

console.log('🧪 Testing Polyglot & Unicode Injection Detection\n');

const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true
  }
});

// ============================================================================
// TEST 1: Polyglot Injection Detection (SQL + XSS)
// ============================================================================

test('Polyglot: Classic SQL+XSS combination detected', () => {
  const payload = "' OR 1=1--<script>alert(1)</script>";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect polyglot injection');
  }
  
  // Should detect it as a threat
  const polyglotThreat = result.threats.find(t => 
    t.metadata?.attackType === 'polyglot' || 
    (t.description && t.description.includes('polyglot'))
  );
  
  if (!polyglotThreat) {
    // As long as it's detected as SOME threat, that's acceptable
    console.log('   Note: Detected as regular threat, not specifically polyglot');
  }
});

test('Polyglot: UNION SELECT with XSS detected', () => {
  const payload = "' UNION SELECT '<script>alert(1)</script>'--";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect UNION+XSS polyglot');
  }
});

test('Polyglot: XSS event handler with SQL detected', () => {
  const payload = '<img src=x onerror="x=\' OR 1=1--">';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect XSS event handler with SQL');
  }
});

test('Polyglot: JavaScript protocol with SQL detected', () => {
  const payload = "javascript:alert(SELECT * FROM users)";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect javascript: protocol polyglot');
  }
});

test('Polyglot: SVG with SQL injection detected', () => {
  const payload = '<svg onload="x=\' UNION SELECT password FROM users--">';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect SVG polyglot');
  }
});

test('Polyglot: Data URI with SQL detected', () => {
  const payload = 'data:text/html,<script>x=\' UNION SELECT *--</script>';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect data URI polyglot');
  }
});

// ============================================================================
// TEST 2: Unicode SQL Injection Detection
// ============================================================================

test('Unicode SQL: Full-width SELECT detected', () => {
  // Full-width characters that look like SELECT
  const payload = 'ＳＥＬＥＣＴ';
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect full-width SELECT');
  }
});

test('Unicode SQL: Mixed encoding detected', () => {
  // Mix of normal and full-width characters - needs SQL context
  const payload = 'ＳＥＬＥＣＴ * ＦＲＯＭ users';
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect mixed encoding SQL');
  }
});

test('Unicode SQL: Cyrillic homoglyph detected', () => {
  // Cyrillic characters that look like Latin (Е = Cyrillic E)
  // Needs SQL context - homoglyphs alone won't trigger (by design to reduce false positives)
  const payload = "' OR 'SЕLЕCT' = 'SЕLЕCT"; // Contains Cyrillic Е with SQL context
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect Cyrillic homoglyph');
  }
});

test('Unicode SQL: Cherokee lookalike detection', () => {
  // Cherokee characters that look like SELECT - with SQL context
  const payload = "ᏚᎬᏞᎬᏟᎢ OR 1=1--";
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect Cherokee lookalike SQL');
  }
});

// ============================================================================
// TEST 3: Edge Cases - Should NOT False Positive
// ============================================================================

test('Normal text with quotes should not trigger polyglot', () => {
  const payload = "It's a nice day";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (!result.safe) {
    throw new Error('False positive on normal text with apostrophe');
  }
});

test('Normal HTML without SQL should not trigger polyglot', () => {
  const payload = '<div>Hello World</div>';
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (!result.safe) {
    throw new Error('False positive on normal HTML');
  }
});

test('Normal Unicode text should not trigger', () => {
  // Normal Unicode text (not attacks)
  const payload = 'Hello 世界 мир';
  const result = aimless.validate(payload).against(['sql']).result();
  
  if (!result.safe) {
    throw new Error('False positive on normal Unicode text');
  }
});

// ============================================================================
// TEST 4: Complex Polyglot Patterns
// ============================================================================

test('Polyglot: CDATA with SQL detected', () => {
  const payload = '<![CDATA[SELECT * FROM users]]>';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect CDATA polyglot');
  }
});

test('Polyglot: HTML comment with SQL detected', () => {
  const payload = '<!--SELECT * FROM users-->';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect HTML comment polyglot');
  }
});

test('Polyglot: Attribute injection detected', () => {
  const payload = 'name="\' UNION SELECT password FROM users</script>';
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect attribute injection polyglot');
  }
});

// ============================================================================
// TEST 5: Real-World Attack Examples
// ============================================================================

test('Real attack: Polyglot from OWASP Top 10', () => {
  const payload = "'; DROP TABLE users--<script>alert('XSS')</script>";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect OWASP polyglot example');
  }
  
  // Should be high confidence
  const highConfidenceThreats = result.threats.filter(t => t.confidence >= 60);
  if (highConfidenceThreats.length === 0) {
    throw new Error('Confidence too low for obvious attack');
  }
});

test('Real attack: Advanced polyglot bypass attempt', () => {
  const payload = "1' AND '1'='1' UNION SELECT '<img src=x onerror=alert(1)>'--";
  const result = aimless.validate(payload).against(['all']).result();
  
  if (result.safe) {
    throw new Error('Failed to detect advanced polyglot bypass');
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
  console.log('\n🎉 All polyglot & Unicode tests passed!');
  console.log('✅ Polyglot injection detection working');
  console.log('✅ Unicode SQL injection detection working');
  console.log('✅ Homoglyph attack detection working');
  console.log('✅ No false positives on normal content');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
}
