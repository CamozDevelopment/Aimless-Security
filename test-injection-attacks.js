// Test SQL injection attacks against the demo server

async function testAttack(name, url) {
  console.log(`\n🔍 Testing: ${name}`);
  console.log(`   URL: ${url}`);
  
  try {
    const response = await fetch(url);
    const status = response.status;
    const data = await response.json();
    
    if (status === 403) {
      console.log(`   ✅ BLOCKED (403 Forbidden)`);
      console.log(`   Message: ${data.message || data.error}`);
      return 'BLOCKED';
    } else if (status === 200) {
      if (data.warning) {
        console.log(`   ❌ VULNERABLE (200 OK) - Attack succeeded!`);
        console.log(`   Warning: ${data.warning}`);
        console.log(`   Exposed ${data.users.length} users:`, data.users.map(u => u.username).join(', '));
        return 'VULNERABLE';
      } else {
        console.log(`   ✅ ALLOWED (Normal query)`);
        console.log(`   Found ${data.users.length} users`);
        return 'ALLOWED';
      }
    } else {
      console.log(`   ⚠️  Unexpected status: ${status}`);
      return 'UNKNOWN';
    }
  } catch (error) {
    console.log(`   ❌ ERROR: ${error.message}`);
    return 'ERROR';
  }
}

async function runTests() {
  console.log('\n=== SQL Injection Protection Test Suite ===\n');
  console.log('Testing Aimless SDK v1.3.3 middleware protection...\n');
  
  const tests = [
    {
      name: 'Normal Query (should allow)',
      url: 'http://localhost:3000/api/search?username=admin'
    },
    {
      name: 'Single Quote Attack (should block)',
      url: "http://localhost:3000/api/search?username=admin'"
    },
    {
      name: 'OR 1=1 Attack (should block)',
      url: "http://localhost:3000/api/search?username=' OR '1'='1"
    },
    {
      name: 'Comment Injection (should block)',
      url: "http://localhost:3000/api/search?username=admin'--"
    },
    {
      name: 'Classic SQL Injection (should block)',
      url: "http://localhost:3000/api/search?username=' OR 1=1--"
    }
  ];
  
  const results = [];
  for (const test of tests) {
    const result = await testAttack(test.name, test.url);
    results.push({ name: test.name, result });
    await new Promise(resolve => setTimeout(resolve, 500)); // Small delay between tests
  }
  
  console.log('\n=== Test Results Summary ===\n');
  let passed = 0;
  let failed = 0;
  
  results.forEach((r, i) => {
    const expected = i === 0 ? 'ALLOWED' : 'BLOCKED';
    const status = r.result === expected ? '✅' : '❌';
    console.log(`${status} ${r.name}: ${r.result} (Expected: ${expected})`);
    
    if (r.result === expected) {
      passed++;
    } else {
      failed++;
    }
  });
  
  console.log(`\n📊 Results: ${passed}/${tests.length} tests passed`);
  
  if (failed > 0) {
    console.log('\n⚠️  SECURITY WARNING: Some attacks were NOT blocked!');
    console.log('🔧 This indicates the middleware is not properly protecting the application.');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed! Application is properly protected.');
    process.exit(0);
  }
}

runTests();
