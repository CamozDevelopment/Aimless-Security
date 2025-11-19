const express = require('express');
const Aimless = require('../dist/index');

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
    anomalyDetection: true,
    trustedOrigins: ['http://localhost:3000']
  },
  logging: {
    enabled: true,
    level: 'info'
  }
});

// Apply RASP middleware
app.use(aimless.middleware());

// Sample routes
app.get('/api/users', (req, res) => {
  const { search } = req.query;
  
  // Check if request was flagged
  if (req.aimless?.threats.length > 0) {
    console.log('Threats detected but not blocked:', req.aimless.threats);
  }
  
  res.json({
    users: [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' }
    ],
    search
  });
});

app.post('/api/users', (req, res) => {
  const { username, email } = req.body;
  
  res.json({
    message: 'User created',
    user: { username, email }
  });
});

app.get('/api/file', (req, res) => {
  const { path } = req.query;
  
  // This will be blocked if path traversal is detected
  res.json({ path });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Aimless Security is active');
  console.log('Try these test URLs:');
  console.log(`  http://localhost:${PORT}/api/users?search=test`);
  console.log(`  http://localhost:${PORT}/api/users?search=' OR '1'='1`);
  console.log(`  http://localhost:${PORT}/api/file?path=../../../etc/passwd`);
});
