/**
 * Aimless Security - Access Control Examples
 * 
 * Shows how to use the endpoint access control system to:
 * - Whitelist allowed APIs
 * - Block unauthorized endpoints
 * - Protect sensitive routes
 * - Set per-endpoint security rules
 */

const express = require('express');
const aimlessSDK = require('aimless-security');

const app = express();
app.use(express.json());

// ============================================================================
// EXAMPLE 1: ALLOWLIST MODE - Only Allow Specific Endpoints
// ============================================================================
const allowlistConfig = {
  rasp: {
    blockMode: true, // Enable blocking
    accessControl: {
      mode: 'allowlist', // Only allowed endpoints can be accessed
      defaultAction: 'block', // Block everything not explicitly allowed
      allowedEndpoints: [
        // Public endpoints
        { path: '/', methods: ['GET'] },
        { path: '/health', methods: ['GET'] },
        { path: '/api/status', methods: ['GET'] },
        
        // Authentication endpoints
        { path: '/auth/login', methods: ['POST'] },
        { path: '/auth/register', methods: ['POST'] },
        
        // Public API with wildcard
        { path: '/api/public/*', methods: ['GET'] }, // Allows /api/public/users, /api/public/posts, etc.
        
        // Protected API (requires auth)
        { 
          path: '/api/user/profile', 
          methods: ['GET', 'PUT'],
          requireAuth: true // Must have Authorization header
        }
      ]
    }
  }
};

// app.use(aimlessSDK(allowlistConfig));

// ============================================================================
// EXAMPLE 2: BLOCKLIST MODE - Block Specific Dangerous Endpoints
// ============================================================================
const blocklistConfig = {
  rasp: {
    blockMode: true,
    accessControl: {
      mode: 'blocklist', // Allow everything except blocked endpoints
      blockedEndpoints: [
        '/admin/*', // Block all admin routes
        '/internal/*', // Block internal APIs
        /\/debug.*/, // Block anything starting with /debug (regex)
        '/api/v1/legacy/*', // Block deprecated APIs
      ]
    }
  }
};

// app.use(aimlessSDK(blocklistConfig));

// ============================================================================
// EXAMPLE 3: PROTECTED ENDPOINTS - Extra Security for Sensitive Routes
// ============================================================================
const protectedConfig = {
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    accessControl: {
      mode: 'monitor', // Monitor mode for most endpoints
      protectedEndpoints: [
        {
          path: '/api/payments/*',
          maxThreatLevel: 'low', // Block even low-severity threats
          requireAuth: true,
          rateLimit: { maxRequests: 10, windowMs: 60000 } // 10 req/min
        },
        {
          path: '/api/admin/*',
          maxThreatLevel: 'low', // Zero tolerance for admin endpoints
          requireAuth: true,
          methods: ['GET', 'POST', 'PUT', 'DELETE']
        },
        {
          path: '/api/user/delete',
          maxThreatLevel: 'low',
          requireAuth: true,
          methods: ['POST'] // Only POST allowed
        }
      ]
    }
  }
};

// app.use(aimlessSDK(protectedConfig));

// ============================================================================
// EXAMPLE 4: COMBINED - Allowlist + Protected + Custom Auth
// ============================================================================
const productionConfig = {
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    accessControl: {
      mode: 'allowlist',
      defaultAction: 'block',
      requireAuthHeader: 'X-API-Key', // Global auth header requirement
      
      // Public endpoints (no auth)
      allowedEndpoints: [
        { path: '/', methods: ['GET'] },
        { path: '/health', methods: ['GET'] },
        { path: '/api/public/*', methods: ['GET'] },
        { path: '/auth/login', methods: ['POST'] },
        { path: '/auth/register', methods: ['POST'] },
        
        // Authenticated endpoints
        { path: '/api/users', methods: ['GET', 'POST'], requireAuth: true },
        { path: '/api/posts/*', methods: ['GET', 'POST', 'PUT', 'DELETE'], requireAuth: true },
      ],
      
      // Extra protection for sensitive operations
      protectedEndpoints: [
        {
          path: '/api/admin/*',
          maxThreatLevel: 'low', // Stricter security
          requireAuth: true
        },
        {
          path: '/api/payments/*',
          maxThreatLevel: 'low',
          requireAuth: true,
          rateLimit: { maxRequests: 20, windowMs: 60000 }
        }
      ],
      
      // Blocked endpoints
      blockedEndpoints: [
        '/debug/*',
        '/internal/*',
        /.env/
      ]
    }
  },
  logging: {
    enabled: true,
    level: 'info'
  }
};

app.use(aimlessSDK(productionConfig));

// ============================================================================
// EXAMPLE 5: REGEX PATTERNS - Advanced Endpoint Matching
// ============================================================================
const regexConfig = {
  rasp: {
    blockMode: true,
    accessControl: {
      mode: 'allowlist',
      allowedEndpoints: [
        // Match versioned APIs: /api/v1/..., /api/v2/..., etc.
        { path: /^\/api\/v\d+\/.*/, methods: ['GET', 'POST'] },
        
        // Match UUID patterns: /users/123e4567-e89b-12d3-a456-426614174000
        { path: /^\/users\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, methods: ['GET'] },
        
        // Match numeric IDs: /posts/123
        { path: /^\/posts\/\d+$/, methods: ['GET', 'PUT', 'DELETE'], requireAuth: true }
      ]
    }
  }
};

// app.use(aimlessSDK(regexConfig));

// ============================================================================
// EXAMPLE 6: MONITOR MODE - Log Only, Don't Block
// ============================================================================
const monitorConfig = {
  rasp: {
    blockMode: false, // Don't block threats, just log
    injectionProtection: true,
    xssProtection: true,
    accessControl: {
      mode: 'monitor', // Log access patterns but don't enforce
      allowedEndpoints: [
        { path: '/api/*' }
      ]
    }
  },
  logging: {
    enabled: true,
    level: 'info',
    logFile: './security.log'
  }
};

// app.use(aimlessSDK(monitorConfig));

// ============================================================================
// EXAMPLE ROUTES
// ============================================================================

// Public routes
app.get('/', (req, res) => {
  res.json({ message: 'Homepage - Public access' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Auth routes
app.post('/auth/login', (req, res) => {
  res.json({ token: 'fake-jwt-token' });
});

// Public API
app.get('/api/public/users', (req, res) => {
  res.json({ users: ['Alice', 'Bob'] });
});

// Protected API (requires auth)
app.get('/api/user/profile', (req, res) => {
  // Check if request was blocked
  if (req.aimless?.blocked) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  res.json({ 
    message: 'User profile',
    threats: req.aimless?.threats || []
  });
});

// Admin API (extra protection)
app.get('/api/admin/users', (req, res) => {
  res.json({ message: 'Admin panel - extra security applied' });
});

// Payment API (strictest protection)
app.post('/api/payments/charge', (req, res) => {
  res.json({ message: 'Payment processed with maximum security' });
});

// Blocked endpoint
app.get('/debug/config', (req, res) => {
  // This will be blocked by access control
  res.json({ config: 'sensitive data' });
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n🔒 Aimless Security Access Control Examples`);
  console.log(`Server running on http://localhost:${PORT}\n`);
  console.log(`Try these endpoints:`);
  console.log(`  ✅ GET  /              - Public (allowed)`);
  console.log(`  ✅ GET  /health        - Public (allowed)`);
  console.log(`  ✅ POST /auth/login    - Public (allowed)`);
  console.log(`  ✅ GET  /api/public/*  - Public (allowed)`);
  console.log(`  🔐 GET  /api/user/profile - Requires auth`);
  console.log(`  🔐 GET  /api/admin/*   - Protected (extra security)`);
  console.log(`  🔐 POST /api/payments/* - Strictest protection`);
  console.log(`  ❌ GET  /debug/*       - Blocked\n`);
});

module.exports = app;
