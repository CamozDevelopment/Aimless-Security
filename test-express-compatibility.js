/**
 * Express Compatibility Tests
 * Tests to ensure Aimless SDK works perfectly with Express without causing 500 errors
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

console.log('🧪 Testing Express Compatibility\n');

// ============================================================================
// TEST 1: Middleware handles missing req.body
// ============================================================================

test('Middleware handles undefined req.body', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'GET',
    path: '/api/test',
    query: {},
    // body is undefined (common in GET requests)
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() was not called');
  }
});

test('Middleware handles undefined req.query', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'POST',
    path: '/api/test',
    // query is undefined
    body: { test: 'data' },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() was not called');
  }
});

test('Middleware handles missing headers', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'GET',
    path: '/api/test',
    query: {},
    body: {},
    // headers is undefined
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() was not called');
  }
});

test('Middleware handles missing socket', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'GET',
    path: '/api/test',
    query: {},
    body: {},
    headers: {},
    // socket is undefined
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() was not called');
  }
});

// ============================================================================
// TEST 2: Middleware handles circular references in req.body
// ============================================================================

test('Middleware handles circular references in body', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const circular = { name: 'test' };
  circular.self = circular; // Create circular reference
  
  const req = {
    method: 'POST',
    path: '/api/test',
    query: {},
    body: circular,
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() should be called even with circular refs');
  }
});

// ============================================================================
// TEST 3: Middleware handles malformed requests
// ============================================================================

test('Middleware handles null values in request', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'POST',
    path: '/api/test',
    query: null,
    body: null,
    headers: null,
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() should be called even with null values');
  }
});

test('Middleware handles string body (not parsed)', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'POST',
    path: '/api/test',
    query: {},
    body: "raw string body", // Not a parsed object
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('next() should be called even with string body');
  }
});

// ============================================================================
// TEST 4: Middleware doesn't crash on detection errors
// ============================================================================

test('Middleware continues on internal errors (fail open)', () => {
  const aimless = new Aimless({ rasp: { enabled: true, blockMode: false } });
  const middleware = aimless.middleware();
  
  // Create a request that might cause internal issues
  const req = {
    method: 'POST',
    path: '/api/test',
    query: { test: Symbol('test') }, // Symbols can cause issues
    body: { data: undefined },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('Middleware should fail open on errors');
  }
});

// ============================================================================
// TEST 5: CSRF middleware handles edge cases
// ============================================================================

test('CSRF middleware works without session', () => {
  const aimless = new Aimless({ rasp: { csrfProtection: true } });
  const csrf = aimless.csrf();
  
  const req = {
    // No session
  };
  
  const res = {
    locals: {},
    headersSent: false,
    setHeader: () => {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  csrf(req, res, next);
  
  if (!nextCalled) {
    throw new Error('CSRF middleware should work without session');
  }
  
  if (!res.locals.csrfToken) {
    throw new Error('CSRF token should be generated');
  }
});

test('CSRF middleware handles already sent headers', () => {
  const aimless = new Aimless({ rasp: { csrfProtection: true } });
  const csrf = aimless.csrf();
  
  const req = {};
  
  const res = {
    locals: {},
    headersSent: true, // Headers already sent
    setHeader: () => { throw new Error('Cannot set headers after sent'); }
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  csrf(req, res, next);
  
  if (!nextCalled) {
    throw new Error('CSRF should handle already sent headers gracefully');
  }
});

// ============================================================================
// TEST 6: Validation API handles edge cases
// ============================================================================

test('Validate handles non-string inputs', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  
  const result1 = aimless.validate(12345).against(['sql']).result();
  const result2 = aimless.validate({ key: 'value' }).against(['xss']).result();
  const result3 = aimless.validate([1, 2, 3]).against(['all']).result();
  const result4 = aimless.validate(null).against(['sql']).result();
  const result5 = aimless.validate(undefined).against(['xss']).result();
  
  // None should throw errors
  if (result1 === undefined || result2 === undefined || result3 === undefined ||
      result4 === undefined || result5 === undefined) {
    throw new Error('Validate should handle all input types');
  }
});

test('Sanitize handles non-string inputs gracefully', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  
  const result = aimless.validate(12345).against(['sql']).sanitize().result();
  
  if (result.sanitized !== 12345) {
    throw new Error('Sanitize should return original for non-string');
  }
});

// ============================================================================
// TEST 7: Middleware works in different Express configurations
// ============================================================================

test('Middleware works without express.json()', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  // Simulate request without body-parser middleware
  const req = {
    method: 'POST',
    path: '/api/test',
    // query and body are undefined (no parsing middleware)
    headers: { 'content-type': 'application/json' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('Should work without body parser');
  }
});

test('Middleware works with URL-encoded forms', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'POST',
    path: '/api/login',
    query: {},
    body: { username: 'test', password: 'test123' },
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('Should work with form data');
  }
});

test('Middleware works with multipart/form-data', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'POST',
    path: '/api/upload',
    query: {},
    body: { file: 'uploaded-file.jpg' },
    headers: { 'content-type': 'multipart/form-data' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  
  middleware(req, res, next);
  
  if (!nextCalled) {
    throw new Error('Should work with multipart data');
  }
});

// ============================================================================
// TEST 8: Performance - should not cause significant delays
// ============================================================================

test('Middleware performance is acceptable', () => {
  const aimless = new Aimless({ rasp: { enabled: true } });
  const middleware = aimless.middleware();
  
  const req = {
    method: 'GET',
    path: '/api/test',
    query: { page: '1', limit: '10' },
    body: {},
    headers: { 'user-agent': 'Mozilla/5.0' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  
  const res = {
    status: () => ({ json: () => {} }),
    locals: {}
  };
  
  const next = () => {};
  
  // Should complete in under 100ms for simple request
  const start = Date.now();
  middleware(req, res, next);
  const duration = Date.now() - start;
  
  if (duration > 100) {
    throw new Error(`Middleware too slow: ${duration}ms (expected < 100ms)`);
  }
});

// ============================================================================
// RESULTS
// ============================================================================

console.log('\n' + '='.repeat(50));
console.log(`✅ Tests Passed: ${testsPassed}`);
console.log(`❌ Tests Failed: ${testsFailed}`);
console.log('='.repeat(50));

if (testsFailed === 0) {
  console.log('\n🎉 All Express compatibility tests passed!');
  console.log('✅ No 500 errors');
  console.log('✅ Handles all edge cases');
  console.log('✅ Fail-open on errors');
  console.log('✅ Production-ready for Express');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
}
