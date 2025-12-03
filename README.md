# 🛡️ Aimless Security

<div align="center">

![Aimless Security](https://img.shields.io/badge/Aimless-Security-0ea5e9?style=for-the-badge&logo=shield&logoColor=white)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node Version](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen?style=flat-square)](https://nodejs.org)
[![GitHub stars](https://img.shields.io/github/stars/CamozDevelopment/Aimless-Security.svg?style=flat-square)](https://github.com/CamozDevelopment/Aimless-Security/stargazers)

**🚀 Protect your Node.js app in 3 lines of code**

Stop SQL injection, XSS, bots, and 10+ attack types automatically

[Quick Start](#-quick-start-3-lines) • [Features](#-features) • [Examples](#-examples) • [Documentation](./docs.html)

</div>

---

## 💡 Why Aimless Security?

- ✅ **3-Line Setup** - Seriously. Copy, paste, protected.
- 🎨 **Beautiful UI** - Custom loading screens with your branding
- 🔔 **Instant Alerts** - Get notified in Slack/Discord when attacks happen
- 🤖 **Auto Bot Blocking** - Stops scrapers, scanners, and automated attacks
- 📊 **Built-in Analytics** - See what's being attacked in real-time
- 🌐 **Works Everywhere** - Express, Next.js, Vercel, AWS Lambda, anywhere
- 🆓 **Completely Free** - MIT licensed, use it anywhere

## 🚀 Quick Start (3 Lines)

### Installation

```bash
npm install CamozDevelopment/Aimless-Security
```

### Setup

```javascript
const express = require('express');
const { Aimless } = require('aimless-sdk');

const app = express();
app.use(express.json());

const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.middleware());  // ← That's it! You're protected 🎉

app.listen(3000);
```

**Done!** Your app is now protected against:
- ✅ SQL Injection
- ✅ XSS Attacks
- ✅ Command Injection
- ✅ Path Traversal
- ✅ NoSQL Injection
- ✅ CSRF Attacks
- ✅ XXE & SSRF
- ✅ Rate Limit Abuse
- ✅ Bot/Scanner Traffic
- ✅ Unicode SQL Injection
- ✅ Polyglot Attacks

## ✨ What's New in v1.3.4

## ✨ What's New in v1.3.4

### 🎨 Custom UI Features
```javascript
const aimless = new Aimless({
  rasp: {
    // Beautiful loading screen while checking security
    loadingScreen: {
      enabled: true,
      message: 'Verifying your request...'
    },
    // Custom message when blocking attacks
    customBlockMessage: 'Contact support@yourcompany.com'
  }
});

app.use(aimless.loading());  // Add before middleware
app.use(aimless.middleware());
```

### 🔔 Webhook Notifications
Get instant alerts in Slack or Discord when attacks happen:

```javascript
webhooks: {
  enabled: true,
  url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
  events: ['block', 'threat']  // What to notify about
}
```

### 🤖 Bot Detection
Automatically detect and block bots, scrapers, and automated attacks:

```javascript
requestFingerprinting: {
  enabled: true,
  blockAutomatedTraffic: true  // Auto-block bots
}
```

### 📊 Security Analytics
Track what's being attacked in real-time:

```javascript
app.get('/analytics', (req, res) => {
  res.json(aimless.getAnalytics());  // Get detailed metrics
});
```

### ⚡ Smart Rate Limiting
Rate limits that adapt based on IP reputation:

```javascript
rateLimiting: {
  enabled: true,
  maxRequests: 100,
  windowMs: 60000,
  dynamicThrottling: true  // Lower limits for suspicious IPs
}
```

## 🎯 Features

### Security Protection
- **SQL Injection** - 30+ patterns including Unicode SQL
- **XSS Protection** - Multi-layer detection with sanitization
- **Polyglot Attacks** - Detects combined SQL+XSS attacks
- **Command Injection** - PowerShell, Bash, file operations
- **Path Traversal** - Directory traversal prevention
- **NoSQL Injection** - MongoDB, Redis, CouchDB
- **CSRF Protection** - Automatic token generation
- **XXE & SSRF** - XML and server-side request forgery
- **Rate Limiting** - Prevent abuse and DoS attacks

### Advanced Features
- **Custom Loading Screens** - Beautiful security check UI
- **Webhook Notifications** - Slack/Discord alerts
- **Bot Detection** - Block automated traffic
- **Security Analytics** - Real-time attack metrics
- **IP Reputation** - Automatic threat scoring
- **Access Control** - Define allowed/blocked endpoints
- **API Fuzzing** - Find vulnerabilities before attackers do

## 📖 Examples

### Basic Protection

```javascript
const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.middleware());
```

### Full Features Setup

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    
    // Custom UI
    customBlockMessage: 'For support: security@example.com',
    loadingScreen: {
      enabled: true,
      message: 'Checking security...',
      minDuration: 500
    },
    
    // Webhooks
    webhooks: {
      enabled: true,
      url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK',
      events: ['block', 'threat']
    },
    
    // Bot detection
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true
    },
    
    // Analytics
    analytics: {
      enabled: true,
      retention: 30
    },
    
    // Smart rate limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000,
      dynamicThrottling: true
    }
  }
});

// Add middleware (order matters!)
app.use(aimless.loading());      // 1. Loading screen
app.use(aimless.middleware());   // 2. Security protection
```

### Validate User Input

```javascript
app.post('/api/user', (req, res) => {
  const result = aimless.validate(req.body.username)
    .against(['sql', 'xss'])
    .sanitize()
    .result();
    
  if (!result.safe) {
    return res.status(403).json({ error: 'Invalid input' });
  }
  
  // Use result.sanitized safely
  createUser(result.sanitized);
});
```

### CSRF Protection

```javascript
app.use(aimless.csrf());  // Adds CSRF tokens

app.get('/form', (req, res) => {
  res.send(`
    <form method="POST">
      <input type="hidden" value="${res.locals.csrfToken}">
      <button>Submit</button>
    </form>
  `);
});
```

### Check Security Analytics

```javascript
app.get('/admin/security', (req, res) => {
  const analytics = aimless.getAnalytics();
  res.json({
    totalRequests: analytics.totalRequests,
    threats: analytics.threatsDetected,
    blocked: analytics.threatsBlocked,
    topAttackTypes: analytics.topAttackTypes,
    topAttackIPs: analytics.topAttackIPs
  });
});
```

## 🎨 Customization

### Custom Loading Screen

The loading screen shows while Aimless checks requests. Perfect for user-facing apps:

```javascript
loadingScreen: {
  enabled: true,
  message: 'Verifying your request security...',
  minDuration: 1000  // Show for at least 1 second
}
```

Features:
- Dark theme design with your logo
- Smooth animations
- Customizable message
- Only shows on HTML responses

### Webhook Alerts

Get notified instantly when attacks happen:

**Discord:**
```javascript
webhooks: {
  enabled: true,
  url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK/URL',
  events: ['block', 'threat', 'rateLimit']
}
```

**Slack:**
```javascript
webhooks: {
  enabled: true,
  url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
  events: ['all']
}
```

### Bot Detection

Automatically identify and block:
- curl, wget, python-requests
- Headless browsers (Puppeteer, Selenium)
- Security scanners (SQLMap, Burp, ZAP)
- Missing browser headers
- Suspicious patterns

```javascript
requestFingerprinting: {
  enabled: true,
  blockAutomatedTraffic: true
}
```

## 📊 API Reference

### Core Methods

- `aimless.middleware()` - Main security middleware
- `aimless.loading()` - Loading screen middleware
- `aimless.csrf()` - CSRF protection
- `aimless.validate(input)` - Validate user input
- `aimless.sanitize(text)` - Sanitize output
- `aimless.getAnalytics()` - Get security metrics
- `aimless.getIPReputation(ip)` - Get IP score (0-100)

### Configuration Options

```javascript
{
  rasp: {
    enabled: boolean,              // Enable protection
    blockMode: boolean,            // Block threats (false = monitor)
    customBlockMessage: string,    // Custom block message
    loadingScreen: { ... },        // Loading screen config
    webhooks: { ... },             // Webhook config
    requestFingerprinting: { ... },// Bot detection
    analytics: { ... },            // Analytics config
    rateLimiting: { ... }          // Rate limit config
  },
  logging: {
    enabled: boolean,
    level: 'info' | 'warn' | 'error'
  }
}
```

## 🚀 Deployment

### Vercel / Next.js

```javascript
// pages/api/[...all].js
import { Aimless } from 'aimless-sdk';

const aimless = new Aimless({ rasp: { enabled: true } });

export default async function handler(req, res) {
  // Analyze request
  const threats = aimless.analyze({
    method: req.method,
    path: req.url,
    query: req.query,
    body: req.body,
    headers: req.headers,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
  });

  // Block if threats found
  if (threats.length > 0) {
    return res.status(403).json({ error: 'Request blocked' });
  }

  // Your API logic
  res.json({ status: 'ok' });
}
```

### AWS Lambda

Works out of the box with serverless frameworks!

### Express

See examples above - just `app.use(aimless.middleware())`

## 📚 More Documentation

- [Complete Documentation](./docs.html) - Full API reference
- [Examples](./examples/) - Working code examples
- [Changelog](./CHANGELOG.md) - Version history

## 🤝 Contributing

Contributions welcome! Please see our contributing guidelines.

## 📄 License

MIT - Use it anywhere, for free!

## 💬 Support

- 🐛 [Report Issues](https://github.com/CamozDevelopment/Aimless-Security/issues)
- ⭐ [Star on GitHub](https://github.com/CamozDevelopment/Aimless-Security)
- 📧 Contact: [CamozDevelopment](https://github.com/CamozDevelopment)

---

<div align="center">

**Made with ❤️ for the Node.js community**

[⬆ Back to top](#-aimless-security)

</div>