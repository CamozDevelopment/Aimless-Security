# Aimless Security - Quick Reference Card

## Installation
```bash
npm install aimless-security
```

## Quick Start (Express)
```javascript
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false, // Start with detection only
    trustedOrigins: ['https://yourdomain.com']
  }
});

app.use(aimless.middleware());
```

## Quick Start (Next.js/Vercel)
```javascript
// next.config.js
module.exports = {
  experimental: {
    serverComponentsExternalPackages: ['aimless-security']
  }
}

// app/api/route.ts
export const runtime = 'nodejs'; // REQUIRED!

import { Aimless } from 'aimless-security';
const aimless = new Aimless({ rasp: { blockMode: false } });

export async function POST(request) {
  const body = await request.json();
  
  if (!aimless.isSafe(body.userInput)) {
    return Response.json({ error: 'Invalid input' }, { status: 400 });
  }
  
  // Process safely...
}
```

## Most Used Methods

### Check if Input is Safe
```javascript
const safe = aimless.isSafe(userInput);
if (!safe) {
  // Reject request
}
```

### Sanitize Input
```javascript
const clean = aimless.sanitizeFor(userInput, 'html');
// Contexts: 'html', 'javascript', 'url', 'sql'
```

### One-Line Setup
```javascript
const { middleware, csrf, aimless } = Aimless.quickProtect([
  'https://yourdomain.com'
]);

app.use(middleware);
```

### Check IP Reputation
```javascript
const score = aimless.getIPReputation(req.ip);
if (score < 50) {
  // Block suspicious IP
}
```

### Get Statistics
```javascript
const stats = aimless.getStats();
console.log('Threats blocked:', stats.rasp.threatsBlocked);
```

## Common Patterns

### Validate POST Data
```javascript
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  
  if (!aimless.isSafe(message)) {
    return res.status(400).json({ error: 'Invalid message' });
  }
  
  // Process message...
});
```

### Protect Search Queries
```javascript
app.get('/api/search', (req, res) => {
  const query = req.query.q;
  
  if (!aimless.isSafe(query)) {
    return res.status(400).json({ error: 'Invalid search' });
  }
  
  const results = await db.search(query);
  res.json(results);
});
```

### Safe Wrapper (Production)
```javascript
function safeValidate(input) {
  try {
    return aimless.isSafe(input);
  } catch (error) {
    console.error('Validation failed:', error);
    return true; // Fail open - allow request
  }
}
```

## Configuration Snippets

### Detection Only (No Blocking)
```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false // Just detect and log
  }
});
```

### Maximum Security
```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000
    }
  }
});
```

### Vercel/Serverless Safe Config
```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false, // Start safe
    trustedOrigins: [process.env.NEXT_PUBLIC_APP_URL]
  },
  logging: {
    enabled: true,
    level: 'warn' // Reduce noise in serverless
  }
});
```

## Detection Examples

### SQL Injection Detected ❌
```javascript
aimless.isSafe("' OR 1=1--")  // false
aimless.isSafe("admin'--")     // false
aimless.isSafe("UNION SELECT") // false
```

### XSS Detected ❌
```javascript
aimless.isSafe("<script>alert('xss')</script>")  // false
aimless.isSafe("javascript:alert(1)")            // false
aimless.isSafe("<img src=x onerror=alert(1)>")  // false
```

### Safe Input ✅
```javascript
aimless.isSafe("Hello, World!")           // true
aimless.isSafe("user@example.com")        // true
aimless.isSafe("Regular text message")    // true
```

## Troubleshooting

### Issue: 500 Errors on Vercel
**Solution**: Add `export const runtime = 'nodejs';` to API routes

### Issue: Module Not Found
**Solution**: Add to `next.config.js`:
```javascript
experimental: {
  serverComponentsExternalPackages: ['aimless-security']
}
```

### Issue: All Requests Blocked
**Solution**: Set `blockMode: false` initially, then enable gradually

### Issue: False Positives
**Solution**: Use sanitization instead:
```javascript
const clean = aimless.sanitizeFor(input, 'html');
// Use 'clean' instead of rejecting
```

## Testing Commands

```bash
# Run all tests
npm test

# Full validation
npm run validate

# Build only
npm run build

# Verify import
npm run verify
```

## Resources

- 📖 Full Docs: `README.md`
- 🚀 Vercel Guide: `VERCEL.md`
- 🔧 Examples: `/examples` directory
- 📊 Test Suite: `test-serverless.js`
- 🛡️ Safe Wrapper: `examples/safe-wrapper.js`

## Support

- **GitHub**: Report issues on repository
- **Version**: Check with `npm view aimless-security version`
- **Logs**: Enable with `logging: { enabled: true, level: 'debug' }`

---

**Remember**: Always start with `blockMode: false` in production, then enable after testing!

**Serverless**: Always add `export const runtime = 'nodejs';` to API routes using Aimless.

**Safety**: Wrap all Aimless calls in try-catch for fail-open behavior.
