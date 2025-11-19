/**
 * Aimless Security v1.1.0 - New Features Demo
 * 
 * This example demonstrates all the new features added in v1.1.0
 */

const { Aimless } = require('../dist/index');

console.log('🎯 Aimless Security v1.1.0 - New Features Demo\n');

// ===================================
// 1. Quick Start (One-Line Protection)
// ===================================
console.log('1️⃣  Quick Start Example:');
const { middleware, csrf, aimless } = Aimless.quickProtect([
  'http://localhost:3000'
]);
console.log('✅ App protected with one line of code!\n');

// ===================================
// 2. Fluent Validation API
// ===================================
console.log('2️⃣  Fluent Validation API:');
const userInput = "'; DROP TABLE users; --";
const result = aimless.validate(userInput)
  .against(['sql', 'xss'])
  .sanitize()
  .result();

console.log(`Input: "${userInput}"`);
console.log(`Safe: ${result.safe}`);
console.log(`Sanitized: "${result.sanitized}"`);
console.log(`Threats found: ${result.threats.length}`);
if (result.threats.length > 0) {
  result.threats.forEach(t => {
    console.log(`  - ${t.type}: ${t.description}`);
  });
}
console.log();

// ===================================
// 3. Simple Safety Check
// ===================================
console.log('3️⃣  Simple Safety Check:');
const inputs = [
  "normal text",
  "<script>alert('xss')</script>",
  "SELECT * FROM users",
  "hello@example.com"
];

inputs.forEach(input => {
  const safe = aimless.isSafe(input);
  console.log(`  "${input}" → ${safe ? '✅ Safe' : '❌ Unsafe'}`);
});
console.log();

// ===================================
// 4. Context-Aware Sanitization
// ===================================
console.log('4️⃣  Context-Aware Sanitization:');
const maliciousInput = '<script>alert("xss")</script>';

console.log(`Original: "${maliciousInput}"`);
console.log(`For HTML: "${aimless.sanitizeFor(maliciousInput, 'html')}"`);
console.log(`For JavaScript: "${aimless.sanitizeFor(maliciousInput, 'javascript')}"`);
console.log(`For URL: "${aimless.sanitizeFor(maliciousInput, 'url')}"`);
console.log();

// ===================================
// 5. Validate and Sanitize Together
// ===================================
console.log('5️⃣  Validate and Sanitize Together:');
const dirtyInput = "Hello <b>World</b> OR 1=1";
const validated = aimless.validateAndSanitize(dirtyInput);

console.log(`Input: "${dirtyInput}"`);
console.log(`Safe: ${validated.safe}`);
console.log(`Sanitized: "${validated.sanitized}"`);
console.log(`Threats: ${validated.threats.length}`);
console.log();

// ===================================
// 6. Enhanced Detection with Confidence
// ===================================
console.log('6️⃣  Enhanced Detection with Confidence Scores:');
const sqlAttacks = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "1' UNION SELECT * FROM passwords--",
  "admin' AND 1=1--"
];

sqlAttacks.forEach(attack => {
  const threats = aimless.analyze({
    method: 'POST',
    path: '/login',
    body: { username: attack },
    ip: '192.168.1.100'
  });
  
  if (threats.length > 0) {
    const threat = threats[0];
    const confidence = threat.metadata?.confidence || 'unknown';
    console.log(`  "${attack}"`);
    console.log(`    → ${threat.type} (Confidence: ${confidence}, Severity: ${threat.severity})`);
  }
});
console.log();

// ===================================
// 7. IP Reputation System
// ===================================
console.log('7️⃣  IP Reputation System:');

// Simulate some requests from different IPs
const ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];

ips.forEach((ip, index) => {
  // Simulate varying levels of malicious activity
  for (let i = 0; i < (index + 1) * 20; i++) {
    aimless.analyze({
      method: 'POST',
      path: `/api/test${i}`,
      body: { data: "' OR 1=1" },
      ip: ip
    });
  }
});

console.log('IP Reputation Scores:');
ips.forEach(ip => {
  const reputation = aimless.getIPReputation(ip);
  const status = reputation > 80 ? '✅ Good' : reputation > 50 ? '⚠️  Suspicious' : '❌ Bad';
  console.log(`  ${ip}: ${reputation}/100 ${status}`);
});
console.log();

// ===================================
// 8. Manual IP Blocking
// ===================================
console.log('8️⃣  Manual IP Blocking:');
const maliciousIP = '10.0.0.99';
aimless.setIPBlocked(maliciousIP, true);
console.log(`Blocked ${maliciousIP} manually`);

const afterBlock = aimless.getIPReputation(maliciousIP);
console.log(`Reputation after blocking: ${afterBlock}/100`);
console.log();

// ===================================
// 9. Security Statistics
// ===================================
console.log('9️⃣  Security Statistics:');
const stats = aimless.getStats();
console.log('RASP Statistics:');
console.log(`  Total IPs tracked: ${stats.rasp.totalIPs || 'N/A'}`);
console.log(`  Blocked IPs: ${stats.rasp.blockedIPs || 'N/A'}`);
console.log(`  Total requests analyzed: ${stats.rasp.totalRequests || 'N/A'}`);
console.log(`  Unique fingerprints: ${stats.rasp.uniqueFingerprints || 'N/A'}`);
console.log();

// ===================================
// 10. Advanced CSRF with Token Info
// ===================================
console.log('🔟 Advanced CSRF Protection:');
const sessionId = 'user-session-123';
const csrfToken = aimless.generateCSRFToken(sessionId);

console.log(`CSRF Token generated: ${csrfToken.substring(0, 20)}...`);

// Get the CSRF detector
const csrfDetector = aimless.rasp.getCSRFDetector();

// Validate token
const isValid = csrfDetector.validateToken(sessionId, csrfToken);
console.log(`Token validated: ${isValid}`);

// Test with one-time use
const oneTimeValid = csrfDetector.validateToken(sessionId, csrfToken, true);
console.log(`Token validated (one-time): ${oneTimeValid}`);

// Try to use again (should fail with one-time)
const oneTimeValidAgain = csrfDetector.validateToken(sessionId, csrfToken, true);
console.log(`Token reused (should fail): ${oneTimeValidAgain}`);
console.log();

// ===================================
// 11. Direct Detector Access
// ===================================
console.log('1️⃣1️⃣  Direct Detector Access:');

const injectionDetector = aimless.rasp.getInjectionDetector();
const xssDetector = aimless.rasp.getXSSDetector();
const anomalyDetector = aimless.rasp.getAnomalyDetector();

console.log('Available detectors:');
console.log('  ✅ InjectionDetector');
console.log('  ✅ XSSDetector (with context-aware sanitization)');
console.log('  ✅ CSRFDetector (with timing-safe comparison)');
console.log('  ✅ AnomalyDetector (with IP reputation)');
console.log();

// Custom XSS detection with context
const xssPayload = '<img src=x onerror=alert(1)>';
const xssThreats = xssDetector.detect(xssPayload);

console.log(`XSS Detection: "${xssPayload}"`);
if (xssThreats.length > 0) {
  xssThreats.forEach(t => {
    const confidence = t.metadata?.confidence || 'unknown';
    console.log(`  ⚠️  Detected: ${t.description}`);
    console.log(`     Confidence: ${confidence}`);
    console.log(`     Type: ${t.metadata?.type}`);
  });
}
console.log();

// ===================================
// Summary
// ===================================
console.log('✨ v1.1.0 New Features Summary:');
console.log('  ✅ Quick start with Aimless.quickProtect()');
console.log('  ✅ Fluent validation API');
console.log('  ✅ Context-aware sanitization');
console.log('  ✅ Confidence scoring for all detections');
console.log('  ✅ IP reputation system with auto-blocking');
console.log('  ✅ Enhanced CSRF with one-time tokens');
console.log('  ✅ Security statistics and monitoring');
console.log('  ✅ Direct detector access for advanced use cases');
console.log('  ✅ Backward compatible with v1.0.x');
console.log();

console.log('🎉 All new features demonstrated successfully!');
console.log('📚 See UPGRADING.md for migration guide');
console.log('📖 See CHANGELOG.md for detailed release notes');
