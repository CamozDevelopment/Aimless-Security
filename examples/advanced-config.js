const express = require('express');
const session = require('express-session');
const Aimless = require('../dist/index');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Initialize Aimless Security with advanced configuration
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    trustedOrigins: [
      'http://localhost:3000',
      'https://yourdomain.com'
    ],
    maxRequestSize: 5 * 1024 * 1024, // 5MB
    rateLimiting: {
      enabled: true,
      maxRequests: 50,
      windowMs: 60000 // 1 minute
    }
  },
  fuzzing: {
    enabled: true,
    maxPayloads: 100,
    timeout: 5000,
    authBypassTests: true,
    rateLimitTests: true,
    graphqlIntrospection: true
  },
  logging: {
    enabled: true,
    level: 'debug'
  }
});

// Apply CSRF middleware (adds token to response)
app.use(aimless.csrf());

// Apply RASP middleware
app.use(aimless.middleware());

// Custom threat logging middleware
app.use((req, res, next) => {
  if (req.aimless && req.aimless.threats.length > 0) {
    // Log to your monitoring service
    console.log('Security Event:', {
      timestamp: new Date().toISOString(),
      ip: req.ip,
      path: req.path,
      method: req.method,
      threats: req.aimless.threats.map(t => ({
        type: t.type,
        severity: t.severity,
        description: t.description
      }))
    });
  }
  next();
});

// Login page with CSRF token
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
    </head>
    <body>
      <h1>Login</h1>
      <form method="POST" action="/login">
        <input type="hidden" name="_csrf" value="${res.locals.csrfToken}">
        <div>
          <label>Username:</label>
          <input type="text" name="username" required>
        </div>
        <div>
          <label>Password:</label>
          <input type="password" name="password" required>
        </div>
        <button type="submit">Login</button>
      </form>
      <p>CSRF Token: ${res.locals.csrfToken}</p>
    </body>
    </html>
  `);
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Your authentication logic here
  if (username === 'admin' && password === 'password123') {
    req.session.user = { username };
    res.json({ success: true, message: 'Login successful' });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Protected API endpoint
app.get('/api/sensitive-data', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const data = {
    secretInfo: 'This is sensitive data',
    user: req.session.user
  };
  
  res.json(data);
});

// Endpoint demonstrating XSS sanitization
app.post('/api/comments', (req, res) => {
  const { comment } = req.body;
  
  // Sanitize output to prevent XSS
  const sanitized = aimless.sanitize(comment);
  
  res.json({
    original: comment,
    sanitized,
    saved: sanitized
  });
});

// Admin endpoint (for testing anomaly detection)
app.get('/admin', (req, res) => {
  res.json({ message: 'Admin area' });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    aimless: {
      rasp: 'enabled',
      csrf: 'enabled'
    }
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Aimless Security - Advanced Configuration Active');
  console.log('\nEndpoints:');
  console.log(`  http://localhost:${PORT}/login - Login page with CSRF protection`);
  console.log(`  http://localhost:${PORT}/api/sensitive-data - Protected endpoint`);
  console.log(`  http://localhost:${PORT}/api/comments - XSS sanitization demo`);
  console.log(`  http://localhost:${PORT}/health - Health check`);
  console.log('\nTry testing with malicious inputs:');
  console.log(`  curl "http://localhost:${PORT}/api/sensitive-data?id=' OR 1=1--"`);
  console.log(`  curl -X POST http://localhost:${PORT}/api/comments -H "Content-Type: application/json" -d '{"comment":"<script>alert(1)</script>"}'`);
});
