const express = require('express');
const path = require('path');
const { Aimless } = require('./dist/index.js');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true
  },
  logging: {
    level: 'info'
  }
});

// Add the middleware AFTER body parsers
app.use(aimless.middleware());

// Serve HTML page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User List - Protected by Aimless SDK</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 50px auto;
          padding: 20px;
          background-color: #f5f5f5;
        }
        h1 {
          color: #333;
          text-align: center;
        }
        .protection-badge {
          background: #28a745;
          color: white;
          padding: 5px 15px;
          border-radius: 20px;
          font-size: 12px;
          display: inline-block;
          margin-left: 10px;
        }
        #users-container {
          background: white;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .user-card {
          padding: 15px;
          margin: 10px 0;
          background: #f9f9f9;
          border-left: 4px solid #007bff;
          border-radius: 4px;
        }
        .username {
          font-size: 18px;
          font-weight: bold;
          color: #007bff;
        }
        .test-section {
          background: #fff3cd;
          padding: 20px;
          border-radius: 8px;
          margin-top: 20px;
          border-left: 4px solid #ffc107;
        }
        .test-button {
          background: #dc3545;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 4px;
          cursor: pointer;
          margin: 5px;
        }
        .test-button:hover {
          background: #c82333;
        }
        #test-results {
          margin-top: 15px;
          padding: 15px;
          background: white;
          border-radius: 4px;
          min-height: 50px;
        }
        .blocked {
          color: #28a745;
          font-weight: bold;
        }
        .vulnerable {
          color: #dc3545;
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <h1>User Directory <span class="protection-badge">🛡️ Protected</span></h1>
      <div id="users-container">
        <p class="loading">Loading users...</p>
      </div>

      <div class="test-section">
        <h3>🔒 Security Test - Try SQL Injection</h3>
        <p>Click the buttons below to test if Aimless SDK blocks SQL injection attempts:</p>
        <button class="test-button" onclick="testInjection(\\"admin' OR '1'='1\\")">Test: admin' OR '1'='1</button>
        <button class="test-button" onclick="testInjection(\\"admin'--\\")">Test: admin'--</button>
        <button class="test-button" onclick="testInjection(\\"' OR 1=1--\\")">Test: ' OR 1=1--</button>
        <button class="test-button" onclick="testNormal(\\"admin\\")">Test: Normal Query</button>
        <div id="test-results"></div>
      </div>

      <script>
        // Load normal users
        fetch('/api/users')
          .then(response => response.json())
          .then(data => {
            const container = document.getElementById('users-container');
            container.innerHTML = data.users.map(user => \`
              <div class="user-card">
                <div class="username">\${user.username}</div>
              </div>
            \`).join('');
          })
          .catch(error => {
            document.getElementById('users-container').innerHTML = 
              '<p style="color: red;">Error loading users</p>';
          });

        // Test SQL injection
        function testInjection(payload) {
          const resultsDiv = document.getElementById('test-results');
          resultsDiv.innerHTML = '<p>Testing SQL injection with: <code>' + payload + '</code></p><p>⏳ Sending request...</p>';
          
          fetch('/api/search?username=' + encodeURIComponent(payload))
            .then(response => {
              if (response.status === 403) {
                return response.json().then(data => {
                  resultsDiv.innerHTML = \`
                    <p class="blocked">✅ BLOCKED BY AIMLESS SDK</p>
                    <p>Payload: <code>\${payload}</code></p>
                    <p>Status: 403 Forbidden</p>
                    <p>Message: \${data.message}</p>
                    <p>✅ Your application is protected!</p>
                  \`;
                });
              }
              return response.json().then(data => {
                if (data.warning) {
                  resultsDiv.innerHTML = \`
                    <p class="vulnerable">⚠️ VULNERABILITY EXPOSED</p>
                    <p>Payload: <code>\${payload}</code></p>
                    <p>Status: 200 OK (Should be blocked!)</p>
                    <p>Warning: \${data.warning}</p>
                    <p>Exposed \${data.users.length} users with sensitive data!</p>
                    <pre>\${JSON.stringify(data.users, null, 2)}</pre>
                  \`;
                } else {
                  resultsDiv.innerHTML = \`
                    <p>Normal response: \${data.users.length} users found</p>
                  \`;
                }
              });
            })
            .catch(error => {
              resultsDiv.innerHTML = '<p class="vulnerable">Error: ' + error.message + '</p>';
            });
        }

        function testNormal(username) {
          const resultsDiv = document.getElementById('test-results');
          resultsDiv.innerHTML = '<p>Testing normal query: <code>' + username + '</code></p><p>⏳ Sending request...</p>';
          
          fetch('/api/search?username=' + encodeURIComponent(username))
            .then(response => response.json())
            .then(data => {
              resultsDiv.innerHTML = \`
                <p class="blocked">✅ NORMAL QUERY ALLOWED</p>
                <p>Query: <code>\${username}</code></p>
                <p>Results: \${data.users.length} users found</p>
              \`;
            })
            .catch(error => {
              resultsDiv.innerHTML = '<p style="color: red;">Error: ' + error.message + '</p>';
            });
        }
      </script>
    </body>
    </html>
  `);
});

// API endpoint that returns users
app.get('/api/users', (req, res) => {
  res.json({ 
    users: [
      { username: 'Camoz' },
      { username: 'Daimy' }
    ] 
  });
});

// VULNERABLE endpoint for testing SQL injection protection
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.username;
  
  console.log('🔍 Search request received:', searchTerm);
  
  // Check if Aimless blocked it
  if (req.aimless && req.aimless.blocked) {
    console.log('🛑 Request was already blocked by Aimless');
    return res.status(403).json({ error: 'Blocked by security' });
  }
  
  // Simulated vulnerable SQL query (intentionally unsafe!)
  const simulatedQuery = `SELECT * FROM users WHERE username = '${searchTerm}'`;
  
  // Mock database with users
  const mockDatabase = [
    { id: 1, username: 'Camoz', email: 'camoz@example.com', role: 'admin' },
    { id: 2, username: 'Daimy', email: 'daimy@example.com', role: 'user' },
    { id: 3, username: 'admin', email: 'admin@example.com', role: 'admin', password: 'secret123' }
  ];
  
  // Simulate SQL injection vulnerability
  if (searchTerm && (searchTerm.includes("'") || searchTerm.toLowerCase().includes('or') || searchTerm.includes('--'))) {
    console.log('⚠️  SQL INJECTION DETECTED IN ENDPOINT - This should have been blocked!');
    // This would normally dump all users in a real SQL injection
    return res.json({ 
      query: simulatedQuery,
      warning: 'SQL Injection detected! This response means Aimless did NOT block it.',
      users: mockDatabase 
    });
  }
  
  // Normal search
  const result = mockDatabase.filter(u => u.username === searchTerm);
  res.json({ 
    query: simulatedQuery,
    users: result 
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('\n🚀 Server running on http://localhost:' + PORT);
  console.log('🛡️  Protected by Aimless SDK v1.3.3\n');
  console.log('\n📋 Test URLs:');
  console.log('   Homepage: http://localhost:' + PORT);
  console.log('   Normal:   http://localhost:' + PORT + '/api/search?username=admin');
  console.log("   Attack 1: http://localhost:" + PORT + "/api/search?username=admin'");
  console.log("   Attack 2: http://localhost:" + PORT + "/api/search?username=admin' OR '1'='1");
  console.log("   Attack 3: http://localhost:" + PORT + "/api/search?username=' OR 1=1--");
  console.log('\n🧪 Open http://localhost:' + PORT + ' in your browser to test!\n');
});
