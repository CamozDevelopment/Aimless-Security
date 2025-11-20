/**
 * SECURITY TESTING ONLY - Advanced Threat Detection Tests
 * This file contains INTENTIONAL security test patterns for validation.
 * These are NOT malicious - they test the security detection capabilities.
 * 
 * Purpose: Verify LDAP, Template, JWT, and GraphQL security detection
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

console.log('🧪 Testing Advanced Security Detection\n');
console.log('⚠️  This file contains INTENTIONAL security test patterns');
console.log('    These patterns test detection - they are NOT malicious\n');

const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true
  }
});

// ============================================================================
// TEST 1: Basic Advanced Detector Access
// ============================================================================

test('Advanced detector is accessible', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  if (!detector) {
    throw new Error('Advanced detector not found');
  }
});

// ============================================================================
// TEST 2: LDAP Injection Detection
// ============================================================================

test('LDAP injection: wildcard attack detected', () => {
  const testPattern = 'admin)(&(password=*))';
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectLDAPInjection(testPattern);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect LDAP wildcard injection');
  }
});

test('LDAP injection: filter manipulation detected', () => {
  const testPattern = '*)(uid=*))(|(uid=*';
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectLDAPInjection(testPattern);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect LDAP filter manipulation');
  }
});

test('Legitimate LDAP filters are allowed', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectLDAPInjection('john.doe');
  
  if (threats.length > 0) {
    throw new Error('False positive on legitimate LDAP input');
  }
});

// ============================================================================
// TEST 3: Template Injection Detection
// ============================================================================

test('Template injection: Jinja2 detected', () => {
  const testPattern = '{{7*7}}';
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectTemplateInjection(testPattern);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect Jinja2 template injection');
  }
});

test('Template injection: EL expression detected', () => {
  const testPattern = '${7*7}';
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectTemplateInjection(testPattern);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect EL template injection');
  }
});

test('Normal template-like text is allowed', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.detectTemplateInjection('Hello {name}');
  
  if (threats.length > 0) {
    throw new Error('False positive on normal template text');
  }
});

// ============================================================================
// TEST 4: File Upload Validation
// ============================================================================

test('Dangerous file extensions are detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  const dangerousFiles = ['shell.php', 'backdoor.jsp', 'evil.aspx', 'script.exe'];
  
  dangerousFiles.forEach(filename => {
    const threats = detector.validateFileUpload({ filename });
    if (threats.length === 0) {
      throw new Error(`Failed to detect dangerous file: ${filename}`);
    }
  });
});

test('Safe file extensions are allowed', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  const safeFiles = ['document.pdf', 'image.jpg', 'data.json', 'styles.css'];
  
  safeFiles.forEach(filename => {
    const threats = detector.validateFileUpload({ filename });
    if (threats.length > 0) {
      throw new Error(`False positive on safe file: ${filename}`);
    }
  });
});

test('Double extension attacks are detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.validateFileUpload({ filename: 'image.jpg.php' });
  
  if (threats.length === 0) {
    throw new Error('Failed to detect double extension attack');
  }
});

test('File size limits are enforced', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.validateFileUpload({
    filename: 'large.zip',
    size: 1024 * 1024 * 1024 // 1GB
  });
  
  if (threats.length === 0) {
    throw new Error('Failed to detect oversized file');
  }
});

// ============================================================================
// TEST 5: JWT Token Analysis
// ============================================================================

test('Weak JWT algorithms are detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  // JWT with "alg": "none"
  const weakToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';
  const threats = detector.analyzeJWT(weakToken);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect weak JWT algorithm');
  }
});

test('Malformed JWT tokens are detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  const threats = detector.analyzeJWT('not.a.valid.jwt.token');
  
  if (threats.length === 0) {
    throw new Error('Failed to detect malformed JWT');
  }
});

test('Valid JWT structure is accepted', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  // Valid JWT structure with strong algorithm
  const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const threats = detector.analyzeJWT(validToken);
  
  // Should not flag valid JWT (might warn about other things, but not structure)
  const structureThreats = threats.filter(t => t.description.includes('Malformed'));
  if (structureThreats.length > 0) {
    throw new Error('False positive on valid JWT structure');
  }
});

// ============================================================================
// TEST 6: GraphQL Security
// ============================================================================

test('GraphQL depth attacks are detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  const deepQuery = `
    query {
      user {
        posts {
          comments {
            author {
              posts {
                comments {
                  author {
                    posts {
                      comments {
                        author {
                          name
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  `;
  
  const threats = detector.analyzeGraphQL(deepQuery);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect GraphQL depth attack');
  }
});

test('GraphQL introspection is detected', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  const introspectionQuery = `
    query {
      __schema {
        types {
          name
        }
      }
    }
  `;
  
  const threats = detector.analyzeGraphQL(introspectionQuery);
  
  if (threats.length === 0) {
    throw new Error('Failed to detect GraphQL introspection');
  }
});

test('Normal GraphQL queries are allowed', () => {
  const detector = aimless.rasp.getAdvancedDetector();
  
  const normalQuery = `
    query {
      user(id: "123") {
        name
        email
      }
    }
  `;
  
  const threats = detector.analyzeGraphQL(normalQuery);
  
  if (threats.length > 0) {
    throw new Error('False positive on normal GraphQL query');
  }
});

// ============================================================================
// TEST 7: Integration with Main Detection
// ============================================================================

test('Advanced detection integrates with main RASP', () => {
  const rasp = aimless.rasp;
  
  // Should be able to access all detectors
  if (!rasp.getInjectionDetector()) throw new Error('Missing injection detector');
  if (!rasp.getXSSDetector()) throw new Error('Missing XSS detector');
  if (!rasp.getAdvancedDetector()) throw new Error('Missing advanced detector');
});

// ============================================================================
// RESULTS
// ============================================================================

console.log('\n' + '='.repeat(50));
console.log(`✅ Tests Passed: ${testsPassed}`);
console.log(`❌ Tests Failed: ${testsFailed}`);
console.log('='.repeat(50));

if (testsFailed === 0) {
  console.log('\n🎉 All advanced threat detection tests passed!');
  console.log('✅ LDAP injection detection working');
  console.log('✅ Template injection detection working');
  console.log('✅ File upload validation working');
  console.log('✅ JWT security analysis working');
  console.log('✅ GraphQL security working');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed!');
  process.exit(1);
}
