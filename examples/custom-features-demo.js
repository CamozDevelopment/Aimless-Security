const express = require('express');
const { Aimless } = require('../dist/index.js');

const app = express();
app.use(express.json());

// Configure Aimless with new features
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    
    // NEW: Custom block message
    customBlockMessage: 'For support, contact security@yourcompany.com',
    
    // NEW: Loading screen configuration
    loadingScreen: {
      enabled: true, // Enable security check loading screen
      message: 'Verifying request security...', // Custom message
      minDuration: 800 // Show for at least 800ms
    }
  },
  logging: {
    level: 'info'
  }
});

// IMPORTANT: Loading screen middleware must come FIRST
app.use(aimless.loading());

// Then add the main security middleware
app.use(aimless.middleware());

// Your routes
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Aimless Security Demo</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 50px auto;
          padding: 20px;
        }
        h1 { color: #333; }
        .feature {
          background: #f5f5f5;
          padding: 15px;
          margin: 15px 0;
          border-left: 4px solid #667eea;
          border-radius: 4px;
        }
        .test-links {
          margin: 20px 0;
        }
        .test-links a {
          display: block;
          margin: 10px 0;
          padding: 10px;
          background: #667eea;
          color: white;
          text-decoration: none;
          border-radius: 4px;
        }
        .test-links a:hover {
          background: #5568d3;
        }
        code {
          background: #e8e8e8;
          padding: 2px 6px;
          border-radius: 3px;
          font-family: monospace;
        }
      </style>
    </head>
    <body>
      <h1>🛡️ Aimless Security v1.3.4</h1>
      
      <div class="feature">
        <h3>✅ Feature 1: Custom Block Message</h3>
        <p>When a request is blocked, you now see a custom message after "Request blocked by Aimless Security".</p>
        <p>Example: <code>"Request blocked by Aimless Security. For support, contact security@yourcompany.com"</code></p>
      </div>

      <div class="feature">
        <h3>✅ Feature 2: Security Loading Screen</h3>
        <p>You just saw it! A beautiful loading screen appears while Aimless checks your request for security threats.</p>
        <p>Fully customizable message, duration, and styling.</p>
      </div>

      <div class="feature">
        <h3>✅ Feature 3: Enhanced SQL Injection Detection</h3>
        <p>Now blocks even simple SQL injection attempts like <code>admin'</code></p>
        <p>Previously only blocked complex attacks like <code>' OR 1=1--</code></p>
      </div>

      <h2>Test the Features</h2>
      <div class="test-links">
        <a href="/api/test?q=hello">Normal Request (Should Work)</a>
        <a href="/api/test?q=admin'">SQL Injection Test (Should Block + Show Custom Message)</a>
        <a href="/api/test?q=<script>alert('xss')</script>">XSS Test (Should Block + Show Custom Message)</a>
      </div>

      <h2>Configuration</h2>
      <pre style="background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto;">
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    
    // Custom block message
    customBlockMessage: 'For support, contact security@yourcompany.com',
    
    // Loading screen
    loadingScreen: {
      enabled: true,
      message: 'Verifying request security...',
      minDuration: 800 // milliseconds
    }
  }
});

// IMPORTANT: Order matters!
app.use(aimless.loading());   // Loading screen FIRST
app.use(aimless.middleware()); // Security checks SECOND
      </pre>
    </body>
    </html>
  `);
});

app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Request passed security checks!',
    query: req.query
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n✨ Aimless Security v1.3.4 Demo`);
  console.log(`🚀 Server running on http://localhost:${PORT}\n`);
  console.log(`Features enabled:`);
  console.log(`  ✅ Custom block message`);
  console.log(`  ✅ Security loading screen`);
  console.log(`  ✅ Enhanced SQL injection detection\n`);
  console.log(`Open http://localhost:${PORT} to see it in action!\n`);
});
