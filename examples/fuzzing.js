const Aimless = require('../dist/index');

const aimless = new Aimless({
  fuzzing: {
    enabled: true,
    maxPayloads: 50,
    authBypassTests: true,
    rateLimitTests: true,
    graphqlIntrospection: true
  },
  logging: {
    enabled: true,
    level: 'debug'
  }
});

async function fuzzAPIEndpoint() {
  console.log('Starting API fuzzing test...\n');

  // Test 1: Query parameter fuzzing
  console.log('Test 1: Query Parameter Fuzzing');
  const result1 = await aimless.fuzz({
    url: 'http://localhost:3000/api/users',
    method: 'GET',
    query: {
      search: 'test',
      id: '1'
    }
  });

  console.log(`- Tested ${result1.testedPayloads} payloads`);
  console.log(`- Found ${result1.vulnerabilities.length} potential vulnerabilities`);
  console.log(`- Duration: ${result1.duration}ms\n`);

  // Test 2: POST body fuzzing
  console.log('Test 2: POST Body Fuzzing');
  const result2 = await aimless.fuzz({
    url: 'http://localhost:3000/api/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: {
      username: 'admin',
      password: 'password123'
    }
  });

  console.log(`- Tested ${result2.testedPayloads} payloads`);
  console.log(`- Found ${result2.vulnerabilities.length} potential vulnerabilities`);
  console.log(`- Duration: ${result2.duration}ms\n`);

  // Test 3: GraphQL fuzzing
  console.log('Test 3: GraphQL Fuzzing');
  const result3 = await aimless.fuzz({
    url: 'http://localhost:4000/graphql',
    method: 'POST',
    body: {
      query: '{ users { id name email } }'
    }
  });

  console.log(`- Tested ${result3.testedPayloads} payloads`);
  console.log(`- Found ${result3.vulnerabilities.length} potential vulnerabilities`);
  console.log(`- Duration: ${result3.duration}ms\n`);

  // Display detailed results
  console.log('\nDetailed Vulnerability Report:');
  console.log('='.repeat(50));

  const allVulns = [
    ...result1.vulnerabilities,
    ...result2.vulnerabilities,
    ...result3.vulnerabilities
  ];

  const grouped = allVulns.reduce((acc, vuln) => {
    if (!acc[vuln.type]) acc[vuln.type] = [];
    acc[vuln.type].push(vuln);
    return acc;
  }, {});

  for (const [type, vulns] of Object.entries(grouped)) {
    console.log(`\n${type}: ${vulns.length} findings`);
    vulns.slice(0, 3).forEach(v => {
      console.log(`  [${v.severity}] ${v.description}`);
      if (v.payload) {
        console.log(`  Payload: ${v.payload.substring(0, 50)}...`);
      }
    });
  }
}

// Run fuzzing tests
fuzzAPIEndpoint().catch(console.error);
