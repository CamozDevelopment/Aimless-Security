# Upgrading to v1.1.0

## Overview

Version 1.1.0 is **fully backward compatible** with v1.0.x. All existing code will continue to work without modifications. However, v1.1.0 introduces powerful new features that can enhance your security posture.

## What's New

### Enhanced Detection

All threat detection modules now include:
- **Confidence scores** - Know how certain the detection is
- **More patterns** - 3x more attack patterns detected
- **Better accuracy** - Reduced false positives with context-aware whitelisting

### New Helper Methods

```typescript
const aimless = new Aimless();

// Quick safety check
if (aimless.isSafe(userInput)) {
  // Safe to use
}

// Validate and sanitize in one call
const { safe, sanitized, threats } = aimless.validateAndSanitize(userInput);

// Context-aware sanitization
const htmlSafe = aimless.sanitizeFor(input, 'html');
const jsSafe = aimless.sanitizeFor(input, 'javascript');
const urlSafe = aimless.sanitizeFor(input, 'url');

// Fluent validation API
const result = aimless.validate(userInput)
  .against(['sql', 'xss', 'command'])
  .sanitize()
  .result();

if (!result.safe) {
  console.log('Threats found:', result.threats);
}
```

### IP Reputation & Blocking

```typescript
// Check IP reputation (0-100 score)
const reputation = aimless.getIPReputation('192.168.1.100');
console.log(`IP reputation: ${reputation}/100`);

// Block/unblock IPs manually
aimless.setIPBlocked('192.168.1.100', true);

// Get security statistics
const stats = aimless.getStats();
console.log(`Blocked IPs: ${stats.rasp.blockedIPs}`);
console.log(`Total requests: ${stats.rasp.totalRequests}`);
```

### Quick Start

```typescript
// One-line protection setup
const { middleware, csrf, aimless } = Aimless.quickProtect([
  'http://localhost:3000',
  'https://yourdomain.com'
]);

app.use(middleware);
app.use(csrf);
```

## Migration Examples

### Before (v1.0.x)
```typescript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    trustedOrigins: ['http://localhost:3000']
  }
});

app.use(aimless.middleware());

// Manual validation
const threats = aimless.analyze({
  method: 'POST',
  body: req.body,
  query: req.query
});

if (threats.length > 0) {
  return res.status(403).json({ error: 'Security threat detected' });
}
```

### After (v1.1.0) - Recommended Approach
```typescript
// Option 1: Quick Start
const { middleware, csrf, aimless } = Aimless.quickProtect([
  'http://localhost:3000'
]);

app.use(middleware);
app.use(csrf);

// Option 2: Fluent API
app.post('/api/data', (req, res) => {
  const result = aimless.validate(req.body.userInput)
    .against(['sql', 'xss'])
    .sanitize()
    .result();
    
  if (!result.safe) {
    return res.status(403).json({ 
      error: 'Security threat detected',
      threats: result.threats 
    });
  }
  
  // Use result.sanitized safely
  processData(result.sanitized);
});

// Option 3: Simple safety check
if (!aimless.isSafe(userInput)) {
  return res.status(403).json({ error: 'Invalid input' });
}
```

## Enhanced CSRF Protection

v1.1.0 includes improved CSRF protection:

```typescript
// One-time tokens (more secure)
const token = aimless.generateCSRFToken(sessionId);

// In your CSRF validation middleware
const csrfDetector = aimless.getCSRFDetector();
const isValid = csrfDetector.validateToken(sessionId, token, true); // one-time use

// Check token info
const tokenInfo = csrfDetector.getTokenInfo(sessionId);
console.log(`Token expires in: ${tokenInfo.expiresIn}ms`);

// Manual token revocation
csrfDetector.revokeToken(sessionId);
```

## Improved Anomaly Detection

```typescript
// Get detector for advanced use
const anomalyDetector = aimless.getAnomalyDetector();

// Set custom rate limits
anomalyDetector.setIPBlocked('1.2.3.4', true);

// Clear history for specific IP
anomalyDetector.clearHistory('1.2.3.4');

// Get detailed statistics
const stats = anomalyDetector.getStats();
console.log(`Unique fingerprints: ${stats.uniqueFingerprints}`);
console.log(`Blocked IPs: ${stats.blockedIPs}`);
```

## Context-Aware Sanitization

```typescript
const xssDetector = aimless.getXSSDetector();

// Sanitize for different contexts
const htmlOutput = xssDetector.sanitize(userInput, 'html');
const jsOutput = xssDetector.sanitize(userInput, 'javascript');
const cssOutput = xssDetector.sanitize(userInput, 'css');
const urlOutput = xssDetector.sanitize(userInput, 'url');
const attrOutput = xssDetector.sanitize(userInput, 'attribute');

// Use in templates
<div>${htmlOutput}</div>
<script>var data = '${jsOutput}';</script>
<a href="${urlOutput}">Link</a>
<div style="color: ${cssOutput}">Styled</div>
<img alt="${attrOutput}">
```

## Fuzzing Improvements

```typescript
// Enhanced fuzzing with response analysis
const results = await aimless.fuzz({
  url: 'https://api.example.com/data',
  method: 'POST',
  body: { id: 1 },
  expectedStatus: 200
});

// Check vulnerability scores
results.vulnerabilities.forEach(vuln => {
  const score = vuln.metadata?.vulnerabilityScore || 0;
  console.log(`${vuln.type}: ${score}/100 confidence`);
});
```

## Performance Tips

1. **Use Quick Start for new projects** - Fastest way to get protection
2. **Leverage fluent API** - More readable and maintainable
3. **Monitor IP reputation** - Auto-block malicious actors
4. **Clear history periodically** - For privacy and performance
5. **Use context-aware sanitization** - Reduces over-sanitization

## Breaking Changes

**None** - v1.1.0 is fully backward compatible.

## Need Help?

- [GitHub Issues](https://github.com/CamozDevelopment/Aimless-Security/issues)
- [Documentation](https://github.com/CamozDevelopment/Aimless-Security#readme)
- [Examples](https://github.com/CamozDevelopment/Aimless-Security/tree/main/examples)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for detailed release notes.
