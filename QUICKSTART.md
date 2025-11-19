# Quick Start Guide - Aimless Security

## Installation

```bash
npm install aimless-security
```

## 5-Minute Setup

### Step 1: Install and Import

```javascript
const express = require('express');
const Aimless = require('aimless-security');

const app = express();
app.use(express.json());
```

### Step 2: Initialize Aimless

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true
  }
});
```

### Step 3: Apply Middleware

```javascript
app.use(aimless.middleware());
```

### Step 4: Create Your Routes

```javascript
app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000, () => {
  console.log('Server running with Aimless Security');
});
```

## That's It!

Your API is now protected against:
- ✅ SQL Injection
- ✅ NoSQL Injection  
- ✅ XSS Attacks
- ✅ CSRF Attacks
- ✅ Command Injection
- ✅ Path Traversal
- ✅ Rate Limit Abuse
- ✅ Anomalous Behavior

## Test It

Try these malicious requests to see Aimless in action:

```bash
# SQL Injection attempt - BLOCKED
curl "http://localhost:3000/api/users?id=' OR '1'='1"

# XSS attempt - BLOCKED
curl "http://localhost:3000/api/users?search=<script>alert(1)</script>"

# Path Traversal attempt - BLOCKED
curl "http://localhost:3000/api/file?path=../../../etc/passwd"
```

## Next Steps

- [Read the full documentation](./README.md)
- [Explore examples](./examples/)
- [Configure CSRF protection](./README.md#csrf-protection)
- [Run API fuzzing tests](./examples/fuzzing.js)

## TypeScript

```typescript
import Aimless from 'aimless-security';

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: true }
});

app.use(aimless.middleware());
```

## Advanced Configuration

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    trustedOrigins: ['https://yourdomain.com'],
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000
    }
  },
  logging: {
    enabled: true,
    level: 'info'
  }
});
```

## Support

- 📖 [Full Documentation](./README.md)
- 🐛 [Report Issues](https://github.com/your-repo/issues)
- 💬 [Discussions](https://github.com/your-repo/discussions)
