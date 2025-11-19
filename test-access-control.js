/**
 * Access Control Feature Tests
 * Tests the endpoint access control system
 */

const { Aimless } = require('./dist/index.js');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    testsPassed++;
  } catch (error) {
    console.error(`❌ ${name}`);
    console.error(`   Error: ${error.message}`);
    testsFailed++;
  }
}

console.log('🧪 Testing Access Control Features\n');

// ============================================================================
// TEST 1: Allowlist Mode - Allow Specific Endpoints
// ============================================================================

test('Allowlist mode blocks unmatched endpoints', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        defaultAction: 'block',
        allowedEndpoints: [
          { path: '/' },
          { path: '/api/public/*' }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should allow exact match
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/' });
  if (!result1.allowed) throw new Error('Should allow /');
  
  // Should allow wildcard match
  const result2 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/public/users' });
  if (!result2.allowed) throw new Error('Should allow /api/public/users');
  
  // Should block unmatched
  const result3 = rasp.checkEndpointAccess({ method: 'GET', path: '/admin' });
  if (result3.allowed) throw new Error('Should block /admin');
});

test('Allowlist mode respects method restrictions', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        allowedEndpoints: [
          { path: '/api/users', methods: ['GET', 'POST'] }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should allow GET
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/users' });
  if (!result1.allowed) throw new Error('Should allow GET');
  
  // Should allow POST
  const result2 = rasp.checkEndpointAccess({ method: 'POST', path: '/api/users' });
  if (!result2.allowed) throw new Error('Should allow POST');
  
  // Should block DELETE
  const result3 = rasp.checkEndpointAccess({ method: 'DELETE', path: '/api/users' });
  if (result3.allowed) throw new Error('Should block DELETE');
});

test('Allowlist mode checks authentication requirements', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        allowedEndpoints: [
          { path: '/api/profile', requireAuth: true }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should block without auth header
  const result1 = rasp.checkEndpointAccess({ 
    method: 'GET', 
    path: '/api/profile',
    headers: {}
  });
  if (result1.allowed) throw new Error('Should block without auth');
  
  // Should allow with auth header
  const result2 = rasp.checkEndpointAccess({ 
    method: 'GET', 
    path: '/api/profile',
    headers: { 'authorization': 'Bearer token' }
  });
  if (!result2.allowed) throw new Error('Should allow with auth');
});

// ============================================================================
// TEST 2: Blocklist Mode
// ============================================================================

test('Blocklist mode blocks specific endpoints', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'blocklist',
        blockedEndpoints: ['/admin/*', '/debug/*']
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should allow unblocked
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/users' });
  if (!result1.allowed) throw new Error('Should allow /api/users');
  
  // Should block admin
  const result2 = rasp.checkEndpointAccess({ method: 'GET', path: '/admin/users' });
  if (result2.allowed) throw new Error('Should block /admin/users');
  
  // Should block debug
  const result3 = rasp.checkEndpointAccess({ method: 'GET', path: '/debug/config' });
  if (result3.allowed) throw new Error('Should block /debug/config');
});

test('Blocklist mode supports regex patterns', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'blocklist',
        blockedEndpoints: [/\/internal.*/, /\.env$/]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should block regex match
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/internal/api' });
  if (result1.allowed) throw new Error('Should block /internal/api');
  
  // Should block .env
  const result2 = rasp.checkEndpointAccess({ method: 'GET', path: '/.env' });
  if (result2.allowed) throw new Error('Should block /.env');
  
  // Should allow non-matching
  const result3 = rasp.checkEndpointAccess({ method: 'GET', path: '/public/api' });
  if (!result3.allowed) throw new Error('Should allow /public/api');
});

// ============================================================================
// TEST 3: Monitor Mode
// ============================================================================

test('Monitor mode allows all endpoints', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'monitor'
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should allow everything in monitor mode
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/admin' });
  if (!result1.allowed) throw new Error('Monitor mode should allow all');
  
  const result2 = rasp.checkEndpointAccess({ method: 'DELETE', path: '/debug' });
  if (!result2.allowed) throw new Error('Monitor mode should allow all');
});

// ============================================================================
// TEST 4: Protected Endpoints
// ============================================================================

test('Protected endpoints are detected correctly', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        protectedEndpoints: [
          {
            path: '/api/payments/*',
            maxThreatLevel: 'low'
          }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should find protected rule
  const rule1 = rasp.getProtectionRules({ method: 'POST', path: '/api/payments/charge' });
  if (!rule1) throw new Error('Should find protected rule');
  if (rule1.maxThreatLevel !== 'low') throw new Error('Wrong threat level');
  
  // Should not find for non-protected
  const rule2 = rasp.getProtectionRules({ method: 'GET', path: '/api/users' });
  if (rule2) throw new Error('Should not find rule for unprotected endpoint');
});

// ============================================================================
// TEST 5: Wildcard Patterns
// ============================================================================

test('Wildcard patterns work correctly', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        allowedEndpoints: [
          { path: '/api/*' },
          { path: '/admin/*/settings' }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should match /api/*
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/users' });
  if (!result1.allowed) throw new Error('Should match /api/*');
  
  const result2 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/posts/123' });
  if (!result2.allowed) throw new Error('Should match /api/*');
  
  // Should match /admin/*/settings
  const result3 = rasp.checkEndpointAccess({ method: 'GET', path: '/admin/user/settings' });
  if (!result3.allowed) throw new Error('Should match /admin/*/settings');
  
  // Should not match different path
  const result4 = rasp.checkEndpointAccess({ method: 'GET', path: '/other' });
  if (result4.allowed) throw new Error('Should not match /other');
});

// ============================================================================
// TEST 6: Regex Patterns in Allowlist
// ============================================================================

test('Regex patterns work in allowlist', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        allowedEndpoints: [
          { path: /^\/api\/v\d+\/.*/ }, // Versioned APIs
          { path: /^\/users\/\d+$/ }     // User IDs
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should match versioned API
  const result1 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/v1/users' });
  if (!result1.allowed) throw new Error('Should match /api/v1/users');
  
  const result2 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/v2/posts' });
  if (!result2.allowed) throw new Error('Should match /api/v2/posts');
  
  // Should match user ID
  const result3 = rasp.checkEndpointAccess({ method: 'GET', path: '/users/123' });
  if (!result3.allowed) throw new Error('Should match /users/123');
  
  // Should not match invalid pattern
  const result4 = rasp.checkEndpointAccess({ method: 'GET', path: '/api/users' });
  if (result4.allowed) throw new Error('Should not match /api/users');
});

// ============================================================================
// TEST 7: Global Auth Header Requirement
// ============================================================================

test('Global auth header requirement works', () => {
  const aimless = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        requireAuthHeader: 'X-API-Key',
        allowedEndpoints: [
          { path: '/api/*' }
        ]
      }
    }
  });

  const rasp = aimless.rasp;
  
  // Should block without global auth
  const result1 = rasp.checkEndpointAccess({ 
    method: 'GET', 
    path: '/api/users',
    headers: {}
  });
  if (result1.allowed) throw new Error('Should block without X-API-Key');
  
  // Should allow with global auth
  const result2 = rasp.checkEndpointAccess({ 
    method: 'GET', 
    path: '/api/users',
    headers: { 'x-api-key': 'secret' }
  });
  if (!result2.allowed) throw new Error('Should allow with X-API-Key');
});

// ============================================================================
// TEST 8: Default Action
// ============================================================================

test('Default action controls unmatched endpoints', () => {
  const aimlessAllow = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        defaultAction: 'allow',
        allowedEndpoints: []
      }
    }
  });

  const aimlessBlock = new Aimless({
    rasp: {
      accessControl: {
        mode: 'allowlist',
        defaultAction: 'block',
        allowedEndpoints: []
      }
    }
  });
  
  // Default allow should allow unmatched
  const result1 = aimlessAllow.rasp.checkEndpointAccess({ method: 'GET', path: '/anything' });
  if (!result1.allowed) throw new Error('Default allow should allow unmatched');
  
  // Default block should block unmatched
  const result2 = aimlessBlock.rasp.checkEndpointAccess({ method: 'GET', path: '/anything' });
  if (result2.allowed) throw new Error('Default block should block unmatched');
});

// ============================================================================
// RESULTS
// ============================================================================

console.log('\n' + '='.repeat(50));
console.log(`✅ Tests Passed: ${testsPassed}`);
console.log(`❌ Tests Failed: ${testsFailed}`);
console.log('='.repeat(50));

if (testsFailed === 0) {
  console.log('\n🎉 All access control tests passed!');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
}
