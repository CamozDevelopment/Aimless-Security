# Aimless Security

<div align="center">

![Aimless Security](https://img.shields.io/badge/Aimless-Security-0ea5e9?style=for-the-badge&logo=shield&logoColor=white)

[![npm version](https://img.shields.io/npm/v/aimless-security.svg?style=flat-square)](https://www.npmjs.com/package/aimless-security)
[![npm downloads](https://img.shields.io/npm/dm/aimless-security.svg?style=flat-square)](https://www.npmjs.com/package/aimless-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node Version](https://img.shields.io/node/v/aimless-security.svg?style=flat-square)](https://nodejs.org)
[![GitHub issues](https://img.shields.io/github/issues/yourusername/aimless-security.svg?style=flat-square)](https://github.com/yourusername/aimless-security/issues)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/aimless-security.svg?style=flat-square)](https://github.com/yourusername/aimless-security/stargazers)

**A comprehensive Runtime Application Self-Protection (RASP) and API Fuzzing Engine for Node.js applications**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Examples](#examples)

</div>

---

A comprehensive **Runtime Application Self-Protection (RASP)** and **API Fuzzing Engine** for Node.js applications. Aimless Security provides inline protection against injections, XSS/CSRF attacks, and anomalous behavior, along with intelligent API fuzzing capabilities.

## Features

### 🛡️ Runtime Application Self-Protection (RASP)

- **Injection Protection**: SQL, NoSQL, Command, XXE, SSRF detection
- **XSS Protection**: Direct and encoded XSS attack detection
- **CSRF Protection**: Token-based CSRF validation with origin checking
- **Anomaly Detection**: Rate limiting, suspicious behavior detection, auth bypass attempts
- **Real-time Blocking**: Configurable blocking mode for detected threats

### 🔍 API Fuzzing Engine

- **Smart Parameter Mutation**: Intelligent payload generation for various attack vectors
- **Auth Bypass Detection**: Tests for common authentication vulnerabilities
- **Rate Limit Testing**: Identifies weak rate limiting configurations
- **GraphQL Introspection**: Detects exposed GraphQL schemas
- **Comprehensive Payloads**: SQL, NoSQL, XSS, Command Injection, Path Traversal, and more

## Installation

```bash
npm install aimless-security
```

## Quick Start

### Basic Express Integration

```javascript
const express = require('express');
const Aimless = require('aimless-security');

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

## Best Practices

1. **Start in Monitor Mode**: Test with `blockMode: false` initially
2. **Configure Trusted Origins**: Set `trustedOrigins` for CSRF protection
3. **Tune Rate Limits**: Adjust based on your application's traffic patterns
4. **Review Logs**: Monitor detected threats regularly
5. **Use HTTPS**: Always use HTTPS in production
6. **Keep Updated**: Regularly update to get latest threat signatures

## Examples

See the `/examples` directory for more detailed examples:

- `basic-express.js` - Basic Express integration
- `advanced-config.js` - Advanced configuration
- `fuzzing.js` - API fuzzing examples
- `graphql.js` - GraphQL protection

## Contributing

Contributions are welcome! Please read our contributing guidelines.

## License

MIT

## Support

For issues, questions, or contributions, please visit our GitHub repository.

---

**Note**: Aimless Security is designed to complement, not replace, other security measures. Always follow security best practices and keep your dependencies up to date.
