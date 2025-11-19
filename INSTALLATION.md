# Aimless Security - Installation & Usage Guide

## Installation

```bash
npm install aimless-security
```

Or if you're working locally with this SDK:

```bash
cd AimlessSDK
npm install
npm run build
```

## Running the Demo

To see all features in action:

```bash
node test-demo.js
```

Expected output: All 9 tests should pass with detailed threat detection logs.

## Basic Usage

### 1. Express Integration

```javascript
const express = require('express');
const Aimless = require('aimless-security');

const app = express();
app.use(express.json());

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true
  }
});

app.use(aimless.middleware());

app.listen(3000);
```

### 2. Run Example Server

```bash
node examples/basic-express.js
```

Then test with:
```bash
# Normal request - should work
curl "http://localhost:3000/api/users?search=test"

# SQL injection - should be blocked
curl "http://localhost:3000/api/users?search=' OR '1'='1"

# XSS attack - should be blocked
curl "http://localhost:3000/api/users?search=<script>alert(1)</script>"
```

### 3. API Fuzzing

```bash
node examples/fuzzing.js
```

### 4. Advanced Configuration

```bash
node examples/advanced-config.js
```

## Testing Checklist

### ✅ RASP Protection Tests

- [ ] SQL Injection detection
- [ ] NoSQL Injection detection
- [ ] Command Injection detection
- [ ] XSS detection (direct)
- [ ] XSS detection (encoded)
- [ ] CSRF token generation
- [ ] CSRF validation
- [ ] Path traversal detection
- [ ] XXE detection
- [ ] SSRF detection
- [ ] Rate limiting
- [ ] Anomaly detection
- [ ] Clean request validation

### ✅ Fuzzing Tests

- [ ] Query parameter fuzzing
- [ ] POST body fuzzing
- [ ] Header fuzzing
- [ ] Auth bypass testing
- [ ] Rate limit testing
- [ ] GraphQL introspection
- [ ] Custom payload injection

### ✅ Integration Tests

- [ ] Express middleware integration
- [ ] CSRF middleware integration
- [ ] Custom threat handling
- [ ] Error handling
- [ ] Logging functionality

## Configuration Options

### Minimal Configuration
```javascript
new Aimless({ rasp: { enabled: true } })
```

### Recommended Configuration
```javascript
new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    trustedOrigins: ['https://yourdomain.com']
  },
  logging: {
    enabled: true,
    level: 'info'
  }
})
```

### Maximum Security Configuration
```javascript
new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    trustedOrigins: ['https://yourdomain.com', 'https://app.yourdomain.com'],
    maxRequestSize: 5 * 1024 * 1024, // 5MB
    rateLimiting: {
      enabled: true,
      maxRequests: 50,
      windowMs: 60000
    }
  },
  fuzzing: {
    enabled: true,
    maxPayloads: 100,
    authBypassTests: true,
    rateLimitTests: true,
    graphqlIntrospection: true
  },
  logging: {
    enabled: true,
    level: 'debug'
  }
})
```

## Common Use Cases

### 1. Protect REST API
```javascript
app.use(aimless.middleware());
app.get('/api/users', (req, res) => { /* handler */ });
```

### 2. Protect with CSRF
```javascript
app.use(aimless.csrf());
app.use(aimless.middleware());
app.post('/api/submit', (req, res) => { /* handler */ });
```

### 3. Custom Threat Handling
```javascript
app.use(aimless.middleware());
app.use((req, res, next) => {
  if (req.aimless?.threats.length > 0) {
    // Your custom logic
    logToSIEM(req.aimless.threats);
  }
  next();
});
```

### 4. Sanitize User Input
```javascript
app.post('/api/comment', (req, res) => {
  const safe = aimless.sanitize(req.body.comment);
  // Store safe comment
});
```

### 5. Test Your API
```javascript
const result = await aimless.fuzz({
  url: 'http://localhost:3000/api/login',
  method: 'POST',
  body: { username: 'test', password: 'test' }
});
```

## Troubleshooting

### Issue: Too many false positives
**Solution**: Adjust sensitivity or disable specific protections
```javascript
new Aimless({
  rasp: {
    blockMode: false, // Monitor only
    // or disable specific protections
    commandInjection: false
  }
})
```

### Issue: Performance impact
**Solution**: Reduce rate limit checks or disable anomaly detection
```javascript
new Aimless({
  rasp: {
    anomalyDetection: false,
    rateLimiting: { enabled: false }
  }
})
```

### Issue: CSRF tokens not working
**Solution**: Ensure CSRF middleware comes before RASP middleware
```javascript
app.use(aimless.csrf());  // First
app.use(aimless.middleware());  // Second
```

## Next Steps

1. ✅ Install and run the demo
2. ✅ Try the basic example
3. ✅ Test with malicious inputs
4. ✅ Run fuzzing tests
5. ✅ Integrate into your project
6. ✅ Configure for production
7. ✅ Monitor and tune

## Support

- 📖 Read [README.md](./README.md) for full documentation
- 💡 Check [examples/](./examples/) for more examples
- 🐛 Found a bug? Please report it
- 💬 Questions? Open a discussion

## License

MIT - See [LICENSE](./LICENSE) file
