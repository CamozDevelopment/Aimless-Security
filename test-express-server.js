/**
 * Real Express Server Test
 * This creates an actual Express server to test Aimless SDK integration
 */

const express = require('express');
const { Aimless } = require('./dist/index.js');

const app = express();
const PORT = 3456; // Use different port to avoid conflicts

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Aimless SDK
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true
  },
  logging: {
    level: 'info'
  }
});

// Add Aimless middleware
app.use(aimless.middleware());

// Test routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Aimless SDK Express Server Test',
    status: 'running',
    protected: true
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/users', (req, res) => {
  // This should work fine with normal queries
  const { page, limit } = req.query;
  res.json({ 
    users: [],
    page: page || 1,
    limit: limit || 10
  });
});

app.post('/api/users', (req, res) => {
  // This should work fine with normal data
  const { username, email } = req.body;
  res.json({ 
    created: true,
    user: { username, email }
  });
});

app.post('/api/search', (req, res) => {
  // This should block SQL injection attempts
  const { query } = req.body;
  
  if (req.aimless && req.aimless.blocked) {
    // This shouldn't be reached if middleware blocked it
    return res.status(403).json({ error: 'Blocked by security' });
  }
  
  res.json({ 
    results: [],
    query: query,
    safe: true
  });
});

app.post('/api/comment', (req, res) => {
  // This should block XSS attempts
  const { comment } = req.body;
  
  res.json({ 
    success: true,
    comment: comment
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Express error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`\n🚀 Express server running on http://localhost:${PORT}`);
  console.log('🛡️  Protected by Aimless SDK v1.3.3\n');
  
  // Run tests after server starts
  runTests();
});

// Test function
async function runTests() {
  const tests = [];
  let passed = 0;
  let failed = 0;

  console.log('🧪 Running Express Server Tests...\n');

  // Helper function
  async function testEndpoint(name, options, expectedStatus) {
    try {
      const url = `http://localhost:${PORT}${options.path}`;
      const fetchOptions = {
        method: options.method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        }
      };

      if (options.body) {
        fetchOptions.body = JSON.stringify(options.body);
      }

      const response = await fetch(url, fetchOptions);
      const data = await response.json().catch(() => ({}));

      if (response.status === expectedStatus) {
        console.log(`✅ ${name}`);
        passed++;
        return true;
      } else {
        console.log(`❌ ${name}`);
        console.log(`   Expected ${expectedStatus}, got ${response.status}`);
        console.log(`   Response:`, data);
        failed++;
        return false;
      }
    } catch (error) {
      console.log(`❌ ${name}`);
      console.log(`   Error: ${error.message}`);
      failed++;
      return false;
    }
  }

  // Wait a bit for server to fully start
  await new Promise(resolve => setTimeout(resolve, 500));

  // Test 1: Homepage should work
  await testEndpoint('GET / - Homepage should load', {
    path: '/',
    method: 'GET'
  }, 200);

  // Test 2: Health check should work
  await testEndpoint('GET /api/health - Health check should work', {
    path: '/api/health',
    method: 'GET'
  }, 200);

  // Test 3: Normal GET request with query params
  await testEndpoint('GET /api/users?page=1&limit=10 - Normal query params should work', {
    path: '/api/users?page=1&limit=10',
    method: 'GET'
  }, 200);

  // Test 4: Normal POST request
  await testEndpoint('POST /api/users - Normal POST should work', {
    path: '/api/users',
    method: 'POST',
    body: {
      username: 'testuser',
      email: 'test@example.com'
    }
  }, 200);

  // Test 5: SQL Injection should be blocked
  await testEndpoint('POST /api/search - SQL injection should be BLOCKED', {
    path: '/api/search',
    method: 'POST',
    body: {
      query: "' OR 1=1--"
    }
  }, 403);

  // Test 6: XSS should be blocked
  await testEndpoint('POST /api/comment - XSS attack should be BLOCKED', {
    path: '/api/comment',
    method: 'POST',
    body: {
      comment: '<script>alert("XSS")</script>'
    }
  }, 403);

  // Test 7: Unicode SQL injection should be blocked
  await testEndpoint('POST /api/search - Unicode SQL should be BLOCKED', {
    path: '/api/search',
    method: 'POST',
    body: {
      query: 'ＳＥＬＥＣＴ * FROM users'
    }
  }, 403);

  // Test 8: Polyglot injection should be blocked
  await testEndpoint('POST /api/search - Polyglot attack should be BLOCKED', {
    path: '/api/search',
    method: 'POST',
    body: {
      query: '\' OR 1=1--<script>alert(1)</script>'
    }
  }, 403);

  // Test 9: Normal safe content should work
  await testEndpoint('POST /api/search - Safe query should work', {
    path: '/api/search',
    method: 'POST',
    body: {
      query: 'search term'
    }
  }, 200);

  // Test 10: POST with empty body should work
  await testEndpoint('POST /api/users - Empty body should not crash', {
    path: '/api/users',
    method: 'POST',
    body: {}
  }, 200);

  // Test 11: GET with no query params should work
  await testEndpoint('GET /api/users - No query params should work', {
    path: '/api/users',
    method: 'GET'
  }, 200);

  // Test 12: POST with nested objects should work
  await testEndpoint('POST /api/users - Nested objects should work', {
    path: '/api/users',
    method: 'POST',
    body: {
      username: 'test',
      profile: {
        name: 'Test User',
        age: 25
      }
    }
  }, 200);

  // Print results
  console.log('\n' + '='.repeat(50));
  console.log(`✅ Tests Passed: ${passed}`);
  console.log(`❌ Tests Failed: ${failed}`);
  console.log('='.repeat(50));

  if (failed === 0) {
    console.log('\n🎉 All Express server tests passed!');
    console.log('✅ No 500 errors');
    console.log('✅ Normal requests work');
    console.log('✅ Attack requests blocked');
    console.log('✅ Production-ready for Express\n');
  } else {
    console.log('\n❌ Some tests failed!\n');
  }

  // Shutdown server
  server.close(() => {
    console.log('Server stopped');
    process.exit(failed === 0 ? 0 : 1);
  });
}
