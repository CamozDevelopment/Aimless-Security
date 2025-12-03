const express = require('express');
const { Aimless } = require('../dist/index.js');

const app = express();
app.use(express.json());

// Initialize Aimless with ALL v1.3.4 features
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    
    // ✨ Custom UI Features
    customBlockMessage: 'For support, visit https://support.example.com or contact security@example.com',
    loadingScreen: {
      enabled: true,
      message: 'Verifying your request security...',
      minDuration: 1000 // Show for at least 1 second
    },
    
    // 🔔 Webhook Notifications
    webhooks: {
      enabled: true,
      // Uncomment and add your webhook URL to test
      // url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
      // url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK/URL',
      url: 'https://discord.com/api/webhooks/1445587073040912495/Hh3X0Zj5v-fwPe_oz8ln-beJpmzd9Dnk-ZTzymZNqtqqIq7h5ATS8bkF4WjePya5GfEL', // Mock webhook endpoint
      events: ['block', 'threat', 'rateLimit'],
      includePayload: false, // Set true to include attack payload in webhook
      customHeaders: {
        'X-Security-Source': 'Aimless-Demo',
        'X-Environment': 'development'
      }
    },
    
    // 🤖 Bot Detection & Fingerprinting
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true,
      trustBrowserFingerprints: true
    },
    
    // 📊 Security Analytics
    analytics: {
      enabled: true,
      retention: 30 // Keep analytics for 30 days
    },
    
    // ⚡ Dynamic Rate Limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 10, // Low limit for demo purposes
      windowMs: 60000, // 1 minute
      dynamicThrottling: true,
      suspiciousIPMultiplier: 0.5 // Suspicious IPs get 50% less requests
    }
  },
  
  logging: {
    enabled: true,
    level: 'info'
  }
});

// ============================================
// MIDDLEWARE SETUP (Order matters!)
// ============================================

// 1. Loading screen MUST be first (before security middleware)
app.use(aimless.loading());

// 2. Main security middleware
app.use(aimless.middleware());

// 3. CSRF protection (optional)
app.use(aimless.csrf());

// ============================================
// MOCK WEBHOOK ENDPOINT
// ============================================
const webhookServer = express();
webhookServer.use(express.json());

webhookServer.post('/webhook', (req, res) => {
  console.log('\n🔔 WEBHOOK RECEIVED:', {
    event: req.body.event,
    ip: req.body.ip,
    path: req.body.path,
    threats: req.body.threats?.length || 0,
    reputation: req.body.reputation
  });
  res.status(200).send('OK');
});

webhookServer.listen(3001, () => {
  console.log('📡 Mock webhook server listening on http://localhost:3001');
});

// ============================================
// DEMO ROUTES
// ============================================

// Home page with demo HTML
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Aimless Security v1.3.4 - Feature Demo</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px 20px;
      background: #0f172a;
      color: #e2e8f0;
    }
    h1 {
      background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 50%, #14b8a6 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 10px;
    }
    .feature {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 24px;
      margin: 20px 0;
    }
    .badge {
      display: inline-block;
      background: #0ea5e9;
      color: white;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    a {
      color: #0ea5e9;
      text-decoration: none;
      padding: 8px 16px;
      border: 1px solid #0ea5e9;
      border-radius: 6px;
      display: inline-block;
      margin: 8px 8px 8px 0;
      transition: all 0.3s;
    }
    a:hover {
      background: #0ea5e9;
      color: white;
    }
    .danger { border-color: #ef4444; color: #ef4444; }
    .danger:hover { background: #ef4444; color: white; }
    .warning { border-color: #f59e0b; color: #f59e0b; }
    .warning:hover { background: #f59e0b; color: white; }
    .success { border-color: #10b981; color: #10b981; }
    .success:hover { background: #10b981; color: white; }
    code {
      background: #0f172a;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <h1>🛡️ Aimless Security v1.3.4</h1>
  <p style="color: #94a3b8; margin-top: 0;">Complete Feature Demonstration</p>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>✨ Custom Loading Screen</h2>
    <p>Beautiful security check loading screen with dark theme</p>
    <a href="/">Refresh Page</a>
    <a href="/test" class="success">Safe Route</a>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Notice the loading screen on every HTML page load!
    </p>
  </div>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>💬 Custom Block Messages</h2>
    <p>Friendly messages when requests are blocked</p>
    <a href="/api/test?search=' OR 1=1--" class="danger">Test SQL Injection</a>
    <a href="/api/test?html=<script>alert('xss')</script>" class="danger">Test XSS</a>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Blocked requests include: "For support, visit https://support.example.com..."
    </p>
  </div>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>🔔 Webhook Notifications</h2>
    <p>Real-time alerts to Slack/Discord when attacks detected</p>
    <a href="/api/test?cmd=; rm -rf /" class="danger">Trigger Command Injection</a>
    <a href="/api/test?file=../../etc/passwd" class="danger">Trigger Path Traversal</a>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Check console for webhook notifications (mock endpoint on port 3001)
    </p>
  </div>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>🤖 Bot Detection</h2>
    <p>Automatic detection and blocking of bots and automated attacks</p>
    <code>curl http://localhost:3000/api/test</code>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Try accessing with curl, wget, or Postman - bot score will be high!
    </p>
  </div>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>📊 Security Analytics</h2>
    <p>Detailed metrics about attacks, threats, and performance</p>
    <a href="/admin/analytics" class="success">View Analytics</a>
    <a href="/admin/analytics/summary" class="success">Text Summary</a>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Tracks requests, threats, attack types, IPs, and more!
    </p>
  </div>

  <div class="feature">
    <span class="badge">NEW</span>
    <h2>⚡ Dynamic Rate Limiting</h2>
    <p>Smart limits that adapt based on IP reputation</p>
    <a href="/api/spam" class="warning">Spam Requests (10 req/min limit)</a>
    <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
      Good IPs: 10 req/min | Suspicious IPs: 5 req/min | Bad IPs: Blocked
    </p>
  </div>

  <div class="feature">
    <h2>🔒 All v1.3.2 Features Still Active</h2>
    <p>Unicode SQL injection, Polyglot detection, and all previous features</p>
    <a href="/api/test?unicode=ＳＥＬＥＣＴ * FROM users" class="danger">Unicode SQL</a>
    <a href="/api/test?polyglot=' OR 1=1--<script>alert(1)</script>" class="danger">Polyglot</a>
  </div>

  <hr style="border-color: #334155; margin: 40px 0;">

  <div style="text-align: center; color: #64748b;">
    <p>Protected by <strong style="color: #0ea5e9;">Aimless Security v1.3.4</strong></p>
    <p style="font-size: 14px;">GitHub: <a href="https://github.com/CamozDevelopment/Aimless-Security" target="_blank">CamozDevelopment/Aimless-Security</a></p>
  </div>
</body>
</html>
  `);
});

// API test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'Request processed successfully! ✅',
    query: req.query,
    timestamp: new Date().toISOString(),
    csrfToken: res.locals.csrfToken
  });
});

// Spam endpoint for rate limit testing
app.get('/api/spam', (req, res) => {
  res.json({
    message: 'Spam request received',
    timestamp: new Date().toISOString()
  });
});

// Safe test route
app.get('/test', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Test Page - Aimless Security</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      text-align: center;
      padding: 100px 20px;
    }
    h1 { font-size: 48px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>✅ Security Check Passed!</h1>
  <p>This page loaded successfully through Aimless Security</p>
  <p><a href="/" style="color: white;">← Back to Home</a></p>
</body>
</html>
  `);
});

// Analytics endpoints
app.get('/admin/analytics', (req, res) => {
  const analytics = aimless.getAnalytics();
  res.json(analytics);
});

app.get('/admin/analytics/summary', (req, res) => {
  const summary = aimless.getAnalyticsSummary();
  res.type('text').send(summary);
});

// ============================================
// START SERVER
// ============================================
const PORT = 3000;
app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🛡️  Aimless Security v1.3.4 - Feature Demo Server');
  console.log('='.repeat(60));
  console.log(`\n🌐 Server: http://localhost:${PORT}`);
  console.log(`📊 Analytics: http://localhost:${PORT}/admin/analytics`);
  console.log(`📡 Webhook: http://localhost:3001/webhook`);
  console.log('\n✨ NEW FEATURES:');
  console.log('   • Custom Loading Screen (dark theme)');
  console.log('   • Custom Block Messages');
  console.log('   • Webhook Notifications (Slack/Discord)');
  console.log('   • Bot Detection & Fingerprinting');
  console.log('   • Security Analytics & Metrics');
  console.log('   • Dynamic Rate Limiting');
  console.log('\n💡 Open http://localhost:3000 in your browser to try all features!');
  console.log('='.repeat(60) + '\n');
});
