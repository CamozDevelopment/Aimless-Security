# 📦 Installation Guide

## Install Package

```bash
npm install CamozDevelopment/Aimless-Security
```

That's it! Now add it to your app:

```javascript
const { Aimless } = require('aimless-sdk');

const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.middleware());
```

## Quick Test

Want to see it work? Run this:

```bash
# Create a test file
echo "const express = require('express');
const { Aimless } = require('aimless-sdk');

const app = express();
app.use(express.json());

const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.middleware());

app.get('/test', (req, res) => res.json({ ok: true }));
app.listen(3000, () => console.log('Running on :3000'));
" > test.js

# Run it
node test.js
```

Now try attacking it:

```bash
# Normal request - ✅ WORKS
curl "http://localhost:3000/test?id=123"

# SQL injection - ❌ BLOCKED
curl "http://localhost:3000/test?id=admin'--"

# XSS attack - ❌ BLOCKED
curl "http://localhost:3000/test?name=<script>alert(1)</script>"
```

## Run Examples

The SDK comes with working examples:

```bash
# Clone or download the repo
git clone https://github.com/CamozDevelopment/Aimless-Security.git
cd Aimless-Security

# Install dependencies
npm install

# Run the v1.3.4 demo (shows all features)
npm run build
node examples/v1.3.4-features-demo.js
```

Open http://localhost:3000 to see the interactive demo!

## Configuration Examples

### Minimal (Just Protection)

```javascript
const aimless = new Aimless({ rasp: { enabled: true } });
app.use(aimless.middleware());
```

### Recommended (Protection + UI)

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    loadingScreen: {
      enabled: true,
      message: 'Checking security...'
    }
  }
});

app.use(aimless.loading());
app.use(aimless.middleware());
```

### Full Features (Everything!)

```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    
    // Custom messages
    customBlockMessage: 'Contact security@example.com',
    
    // Loading screen
    loadingScreen: {
      enabled: true,
      message: 'Verifying security...'
    },
    
    // Webhook alerts
    webhooks: {
      enabled: true,
      url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK',
      events: ['block', 'threat']
    },
    
    // Block bots
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true
    },
    
    // Analytics
    analytics: {
      enabled: true,
      retention: 30
    },
    
    // Rate limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000,
      dynamicThrottling: true
    }
  }
});

app.use(aimless.loading());
app.use(aimless.middleware());
```

## Verify Installation

Test that everything works:

```javascript
const { Aimless } = require('aimless-sdk');
const aimless = new Aimless();

// Test SQL detection
console.log('SQL safe?', aimless.isSafe("admin' OR '1'='1"));  // false

// Test XSS detection
console.log('XSS safe?', aimless.isSafe('<script>alert(1)</script>'));  // false

// Test normal input
console.log('Normal safe?', aimless.isSafe('Hello World'));  // true
```

## Common Issues

### "Cannot find module 'aimless-sdk'"

**Fix:** Make sure you installed from GitHub:
```bash
npm install CamozDevelopment/Aimless-Security
```

### CSRF tokens not working

**Fix:** Make sure CSRF middleware comes first:
```javascript
app.use(aimless.csrf());       // ← First
app.use(aimless.middleware()); // ← Second
```

### Too many false positives

**Fix:** Start in monitor mode:
```javascript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false  // Just log, don't block
  }
});
```

### Loading screen not showing

**Fix:** Add `loading()` middleware BEFORE `middleware()`:
```javascript
app.use(aimless.loading());    // ← First (loading screen)
app.use(aimless.middleware()); // ← Second (security)
```

## Next Steps

1. ✅ **Install** - `npm install CamozDevelopment/Aimless-Security`
2. ✅ **Add to app** - 3 lines of code (see above)
3. ✅ **Test it** - Try attacking your own app
4. 📖 **Learn more** - Read [QUICKSTART.md](./QUICKSTART.md)
5. 🎨 **Customize** - Add webhooks, loading screens, analytics

## Need Help?

- 📖 [Quick Start Guide](./QUICKSTART.md) - Get started in 5 minutes
- 📚 [Full Documentation](./README.md) - All features explained
- 💡 [Examples](./examples/) - Working code samples
- 🐛 [Report Issues](https://github.com/CamozDevelopment/Aimless-Security/issues)

---

**Ready to protect your app?** → [Quick Start Guide](./QUICKSTART.md)
