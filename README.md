# Aimless Security

<div align="center">

![Aimless Security](https://img.shields.io/badge/Aimless-Security-0ea5e9?style=for-the-badge&logo=shield&logoColor=white)

[![npm version](https://img.shields.io/npm/v/aimless-security.svg?style=flat-square)](https://www.npmjs.com/package/aimless-security)
[![npm downloads](https://img.shields.io/npm/dm/aimless-security.svg?style=flat-square)](https://www.npmjs.com/package/aimless-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node Version](https://img.shields.io/node/v/aimless-security.svg?style=flat-square)](https://nodejs.org)
[![Vercel Compatible](https://img.shields.io/badge/Vercel-Compatible-black?style=flat-square&logo=vercel)](https://vercel.com)
[![GitHub issues](https://img.shields.io/github/issues/CamozDevelopment/Aimless-Security.svg?style=flat-square)](https://github.com/CamozDevelopment/Aimless-Security/issues)
[![GitHub stars](https://img.shields.io/github/stars/CamozDevelopment/Aimless-Security.svg?style=flat-square)](https://github.com/CamozDevelopment/Aimless-Security/stargazers)

**Advanced Runtime Application Self-Protection (RASP) with AI-like behavioral analysis and intelligent API fuzzing for Node.js**

**✅ Fully compatible with Vercel, Netlify, AWS Lambda, and all serverless platforms**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Vercel Guide](./VERCEL.md) • [Examples](#examples)

</div>

---

A comprehensive **Runtime Application Self-Protection (RASP)** and **API Fuzzing Engine** for Node.js applications. Aimless Security provides inline protection against injections, XSS/CSRF attacks, and anomalous behavior, along with intelligent API fuzzing capabilities.

## ✨ What's New in v1.1.2

- 🌐 **Full Vercel/Serverless Support** - Works on all serverless platforms
- 📦 **Improved Module Resolution** - Better CommonJS/ESM interop
- 🎯 **Confidence Scoring** - Know exactly how certain each detection is
- 🧠 **IP Reputation System** - Automatic behavioral analysis and auto-blocking
- 🔄 **Multi-Layer XSS Detection** - Catches deeply encoded and mutation XSS attacks
- ⚡ **Fluent Validation API** - Elegant, chainable input validation
- 🎨 **Context-Aware Sanitization** - Sanitize for HTML, JavaScript, CSS, URLs
- 📊 **Vulnerability Scoring** - Fuzzing results now include 0-100 risk scores
- 🚀 **Quick Start Helper** - One-line protection setup
- ⏱️ **Timing-Safe Comparisons** - CSRF tokens use crypto.timingSafeEqual

**[See VERCEL.md for Vercel deployment guide](./VERCEL.md)**  
[See UPGRADING.md for migration guide](./UPGRADING.md)

## Features

### 🛡️ Enhanced Runtime Application Self-Protection (RASP)

- **Advanced Injection Protection**: 
  - SQL (20+ patterns including time-based blind, error-based, union-based)
  - NoSQL (MongoDB, CouchDB, Redis, Cassandra)
  - Command (PowerShell, Bash, file redirection, environment variables)
  - XXE (Parameter entities, external DTD, XSLT)
  - SSRF (Cloud metadata, DNS rebinding, localhost variations)
  - Path Traversal (Unicode, double encoding, UNC paths)

- **Multi-Layer XSS Protection**: 
  - Direct and deeply-encoded attack detection
  - Mutation XSS (mXSS) detection
  - Context-aware sanitization (HTML, JavaScript, CSS, URL, Attribute)
  - DOM-based XSS patterns
  - Template injection detection

- **Advanced CSRF Protection**: 
  - Timing-safe token comparison
  - One-time token support
  - Double-submit cookie validation
  - Automatic token cleanup
  - Customizable expiration

- **Intelligent Anomaly Detection**: 
  - IP reputation scoring (0-100)
  - Behavioral fingerprinting
  - Request velocity analysis
  - Auto-blocking malicious IPs
  - Distributed attack detection
  - Rate limiting with burst detection

### 🔍 Enhanced API Fuzzing Engine

- **Smart Response Analysis**: Detects errors, SQL exceptions, stack traces
- **Vulnerability Scoring**: 0-100 risk scores for each finding
- **Dynamic Severity**: Automatically adjusts severity based on response patterns
- **Comprehensive Attack Vectors**: SQL, NoSQL, XSS, Command Injection, Path Traversal
- **GraphQL Support**: Schema introspection and mutation testing
- **Auth Bypass Testing**: Common authentication vulnerability detection

## Installation

```bash
npm install aimless-security
```

## Quick Start

### Option 1: One-Line Protection (Recommended)

```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

// One-line protection with sensible defaults
const { middleware, csrf, aimless } = Aimless.quickProtect([
  'http://localhost:3000',
  'https://yourdomain.com'
]);

app.use(middleware);
app.use(csrf);

// You're protected! 🎉
```

### Option 2: Fluent Validation API

```javascript
const { Aimless } = require('aimless-security');
const aimless = new Aimless();

app.post('/api/user', (req, res) => {
  // Elegant validation chain
  const result = aimless.validate(req.body.username)
    .against(['sql', 'xss', 'command'])
    .sanitize()
    .result();
    
  if (!result.safe) {
    return res.status(403).json({ 
      error: 'Security threat detected',
      threats: result.threats 
    });
  }
  
  // Use result.sanitized safely
  createUser(result.sanitized);
});
```

### Option 3: Traditional Setup

```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

// Initialize Aimless Security
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true
  },
  logging: {
    enabled: true,
    level: 'info'
  }
});

// Apply RASP middleware
app.use(aimless.middleware());

// Your routes
app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);
```

### TypeScript Usage

```typescript
import express from 'express';
import Aimless, { AimlessConfig } from 'aimless-security';

const config: AimlessConfig = {
  rasp: {
    enabled: true,
    blockMode: true,
    trustedOrigins: ['https://yourdomain.com'],
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000
    }
  }
};

const aimless = new Aimless(config);
const app = express();

app.use(express.json());
app.use(aimless.middleware());
```

## Configuration

### RASP Configuration

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,                  // Enable/disable RASP
    injectionProtection: true,      // SQL/NoSQL/Command injection detection
    xssProtection: true,            // XSS attack detection
    csrfProtection: true,           // CSRF protection
    anomalyDetection: true,         // Anomalous behavior detection
    blockMode: true,                // Block threats (false = monitor only)
    trustedOrigins: [               // Trusted origins for CSRF
      'https://yourdomain.com'
    ],
    maxRequestSize: 10485760,      // Max request size in bytes (10MB)
    rateLimiting: {
      enabled: true,
      maxRequests: 100,            // Max requests per window
      windowMs: 60000              // Time window in ms (1 minute)
    }
  }
});
```

### Fuzzing Configuration

```javascript
const aimless = new Aimless({
  fuzzing: {
    enabled: true,
    maxPayloads: 100,              // Max payloads per parameter
    timeout: 5000,                 // Timeout per test in ms
    authBypassTests: true,         // Test auth bypass vulnerabilities
    rateLimitTests: true,          // Test rate limiting
    graphqlIntrospection: true,    // Test GraphQL introspection
    customPayloads: []             // Custom payloads to include
  }
});
```

### Logging Configuration

```javascript
const aimless = new Aimless({
  logging: {
    enabled: true,
    level: 'info',                 // 'debug' | 'info' | 'warn' | 'error'
    logFile: './aimless.log'       // Optional log file path
  }
});
```

## API Reference

### Class: `Aimless`

#### `middleware()`

Returns Express middleware for RASP protection.

```javascript
app.use(aimless.middleware());
```

#### `csrf()`

Returns CSRF protection middleware. Adds CSRF token to response headers.

```javascript
app.use(aimless.csrf());
```

#### `analyze(request)`

Manually analyze a request for threats.

```javascript
const threats = aimless.analyze({
  method: 'POST',
  path: '/api/login',
  query: req.query,
  body: req.body,
  headers: req.headers,
  ip: req.ip
});
```

#### `generateCSRFToken(sessionId)`

Generate a CSRF token for a session.

```javascript
const token = aimless.generateCSRFToken('session-123');
```

#### `sanitize(output)`

Sanitize output to prevent XSS.

```javascript
const safe = aimless.sanitize(userInput);
```

#### `fuzz(target)`

Fuzz test an API endpoint.

```javascript
const result = await aimless.fuzz({
  url: 'https://api.example.com/users',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: {
    username: 'test',
    password: 'test123'
  }
});

console.log(`Found ${result.vulnerabilities.length} potential vulnerabilities`);
```

## Advanced Usage

### CSRF Protection

```javascript
const express = require('express');
const Aimless = require('aimless-security');

const app = express();
const aimless = new Aimless({
  rasp: {
    csrfProtection: true,
    trustedOrigins: ['https://yourdomain.com']
  }
});

// Add CSRF middleware
app.use(aimless.csrf());

// CSRF token is available in res.locals.csrfToken
app.get('/form', (req, res) => {
  res.send(`
    <form method="POST" action="/submit">
      <input type="hidden" name="_csrf" value="${res.locals.csrfToken}">
      <button type="submit">Submit</button>
    </form>
  `);
});

// RASP middleware validates CSRF token
app.use(aimless.middleware());
app.post('/submit', (req, res) => {
  res.send('Success!');
});
```

### Custom Threat Handling

```javascript
app.use((req, res, next) => {
  if (req.aimless && req.aimless.threats.length > 0) {
    // Log threats to your monitoring system
    console.log('Threats detected:', req.aimless.threats);
    
    // Custom response based on threat type
    const hasCritical = req.aimless.threats.some(t => t.severity === 'critical');
    if (hasCritical) {
      return res.status(403).json({ error: 'Access denied' });
    }
  }
  next();
});
```

### API Fuzzing Example

```javascript
const Aimless = require('aimless-security');

const aimless = new Aimless({
  fuzzing: {
    maxPayloads: 50,
    authBypassTests: true,
    graphqlIntrospection: true
  }
});

async function testAPI() {
  const result = await aimless.fuzz({
    url: 'http://localhost:3000/api/users',
    method: 'GET',
    query: {
      id: '1',
      search: 'test'
    }
  });

  console.log(`Tested ${result.testedPayloads} payloads`);
  console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
  
  result.vulnerabilities.forEach(vuln => {
    console.log(`[${vuln.severity}] ${vuln.type}: ${vuln.description}`);
  });
}

testAPI();
```

### GraphQL Protection

```javascript
const aimless = new Aimless({
  fuzzing: {
    graphqlIntrospection: true
  }
});

// Test GraphQL endpoint
const result = await aimless.fuzz({
  url: 'http://localhost:4000/graphql',
  method: 'POST',
  body: {
    query: '{ users { id name } }'
  }
});
```

## Security Threat Types

Aimless detects the following threat types:

- `sql_injection` - SQL injection attempts
- `nosql_injection` - NoSQL injection attempts
- `command_injection` - OS command injection
- `xss` - Cross-site scripting
- `csrf` - Cross-site request forgery
- `path_traversal` - Directory traversal
- `xxe` - XML External Entity
- `ssrf` - Server-side request forgery
- `anomalous_behavior` - Unusual request patterns
- `rate_limit_exceeded` - Rate limit violations
- `auth_bypass_attempt` - Authentication bypass attempts

## Performance Considerations

Aimless is designed to have minimal performance impact:

- Efficient pattern matching using optimized regex
- In-memory threat detection with no external dependencies
- Configurable protection levels
- Optional monitor-only mode for testing

## Testing & Validation

### Running Tests

```bash
# Run all tests
npm test

# Run full validation suite
npm run validate

# Build and test
npm run test:build

# Verify package imports
npm run verify
```

### Test Coverage

Aimless includes 20 comprehensive serverless compatibility tests:

✅ Module loading and initialization  
✅ Configuration handling  
✅ SQL injection detection  
✅ XSS attack detection  
✅ Input sanitization  
✅ IP reputation scoring  
✅ Null/undefined handling  
✅ Large input processing  
✅ Multiple instance isolation  
✅ Node.js crypto integration  

All tests must pass before publishing to NPM.

### Manual Testing

Test SQL injection detection:
```bash
node -e "const { Aimless } = require('aimless-security'); const a = new Aimless(); console.log('Safe:', a.isSafe(\"' OR 1=1--\"));"
# Output: Safe: false
```

Test XSS detection:
```bash
node -e "const { Aimless } = require('aimless-security'); const a = new Aimless(); console.log('Safe:', a.isSafe(\"<script>alert('xss')</script>\"));"
# Output: Safe: false
```

Test safe input:
```bash
node -e "const { Aimless } = require('aimless-security'); const a = new Aimless(); console.log('Safe:', a.isSafe('Hello World'));"
# Output: Safe: true
```

## Best Practices

1. **Start in Monitor Mode**: Test with `blockMode: false` initially
2. **Configure Trusted Origins**: Set `trustedOrigins` for CSRF protection
3. **Tune Rate Limits**: Adjust based on your application's traffic patterns
4. **Review Logs**: Monitor detected threats regularly
5. **Use HTTPS**: Always use HTTPS in production
6. **Keep Updated**: Regularly update to get latest threat signatures
7. **Wrap in Try-Catch**: Always wrap validation in try-catch for fail-open behavior
8. **Test Before Deploy**: Run `npm run validate` before every deployment

## Examples

See the `/examples` directory for more detailed examples:

- `basic-express.js` - Basic Express integration
- `advanced-config.js` - Advanced configuration
- `fuzzing.js` - API fuzzing examples
- `graphql.js` - GraphQL protection
- `vercel-nextjs.ts` - Complete Next.js/Vercel example
- `safe-wrapper.js` - Production-safe error handling wrapper

## Contributing

Contributions are welcome! Please read our contributing guidelines.

## License

MIT

## Support

For issues, questions, or contributions, please visit our GitHub repository.

---

**Note**: Aimless Security is designed to complement, not replace, other security measures. Always follow security best practices and keep your dependencies up to date.
