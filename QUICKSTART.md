# 🚀 Quick Start - Get Protected in 3 Lines

## Install

```bash
npm install CamozDevelopment/Aimless-Security
```

## Add to Your App

```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

// 🛡️ Add Aimless (3 lines)
const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.loading());      // Loading screen
app.use(aimless.middleware());   // Security protection

// Your routes work normally
app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);
```

## ✅ You're Protected!

Your app now blocks:
- SQL Injection (`admin' OR '1'='1`)
- XSS Attacks (`<script>alert('xss')</script>`)
- Command Injection (`; rm -rf /`)
- Path Traversal (`../../../etc/passwd`)
- Bots & Scrapers (curl, wget, etc.)
- Rate Limit Abuse
- And 20+ other attack types

## 🧪 Test It

Try attacking your own app to see Aimless work:

```bash
# SQL Injection - BLOCKED ❌
curl "http://localhost:3000/api/users?id=admin'--"

# XSS Attack - BLOCKED ❌
curl "http://localhost:3000/api/users?name=<script>alert(1)</script>"

# Normal request - ALLOWED ✅
curl "http://localhost:3000/api/users?id=123"
```

## 🎨 Add Features (Optional)

### Custom Loading Screen

Show users a security check screen:

```javascript
const aimless = new Aimless({
  rasp: {
    loadingScreen: {
      enabled: true,
      message: 'Checking security...'
    }
  }
});

app.use(aimless.loading());
app.use(aimless.middleware());
```

### Get Instant Alerts (Discord/Slack)

Get notified when attacks happen:

```javascript
const aimless = new Aimless({
  rasp: {
    webhooks: {
      enabled: true,
      url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK',
      events: ['block', 'threat']
    }
  }
});
```

### Block All Bots

Auto-detect and block automated traffic:

```javascript
const aimless = new Aimless({
  rasp: {
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true
    }
  }
});
```

### Track Security Metrics

See what's being attacked:

```javascript
app.get('/analytics', (req, res) => {
  res.json(aimless.getAnalytics());
});
```

## 📖 Full Example

```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    
    // Custom UI
    customBlockMessage: 'Contact: security@example.com',
    loadingScreen: {
      enabled: true,
      message: 'Verifying security...'
    },
    
    // Webhooks
    webhooks: {
      enabled: true,
      url: 'YOUR_WEBHOOK_URL',
      events: ['block']
    },
    
    // Bot detection
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true
    },
    
    // Rate limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000
    }
  }
});

app.use(aimless.loading());
app.use(aimless.middleware());

// Your routes
app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.post('/api/login', (req, res) => {
  // Input is already sanitized by Aimless
  const { username, password } = req.body;
  res.json({ status: 'ok' });
});

// Check analytics
app.get('/analytics', (req, res) => {
  res.json(aimless.getAnalytics());
});

app.listen(3000, () => {
  console.log('✅ Server running with Aimless Security');
});
```

## 🎯 Validate User Input

```javascript
app.post('/api/comment', (req, res) => {
  // Check if input is safe
  const result = aimless.validate(req.body.comment)
    .against(['sql', 'xss'])
    .sanitize()
    .result();
    
  if (!result.safe) {
    return res.status(403).json({ error: 'Invalid input' });
  }
  
  // Use the sanitized version
  saveComment(result.sanitized);
  res.json({ success: true });
});
```

## 🔒 CSRF Protection

```javascript
app.use(aimless.csrf());  // Add CSRF protection

app.get('/form', (req, res) => {
  res.send(`
    <form method="POST">
      <input type="hidden" value="${res.locals.csrfToken}">
      <button>Submit</button>
    </form>
  `);
});
```

## ☁️ Works Everywhere

### Vercel / Next.js

```javascript
// pages/api/users.js
import { Aimless } from 'aimless-security';

const aimless = new Aimless({ rasp: { enabled: true } });

export default async function handler(req, res) {
  const threats = aimless.analyze({
    method: req.method,
    path: req.url,
    query: req.query,
    body: req.body,
    headers: req.headers,
    ip: req.headers['x-forwarded-for']
  });

  if (threats.length > 0) {
    return res.status(403).json({ error: 'Blocked' });
  }

  res.json({ users: [] });
}
```

### AWS Lambda

```javascript
const { Aimless } = require('aimless-security');
const aimless = new Aimless({ rasp: { enabled: true } });

exports.handler = async (event) => {
  const threats = aimless.analyze({
    method: event.httpMethod,
    path: event.path,
    query: event.queryStringParameters,
    body: JSON.parse(event.body || '{}'),
    headers: event.headers,
    ip: event.requestContext.identity.sourceIp
  });

  if (threats.length > 0) {
    return { statusCode: 403, body: 'Blocked' };
  }

  return { statusCode: 200, body: JSON.stringify({ users: [] }) };
};
```

## 🆘 Need Help?

- 📖 [Full Documentation](./README.md) - All features & config
- 💡 [Examples](./examples/) - Working code examples
- 🐛 [Report Issues](https://github.com/CamozDevelopment/Aimless-Security/issues)

---

**That's it! You're now protected against 20+ attack types** 🎉
