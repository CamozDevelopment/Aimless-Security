// Quick test of SQL injection blocking
async function test() {
  console.log('\n=== Testing SQL Injection Blocking ===\n');
  
  // Test 1: Normal query
  console.log('Test 1: Normal query (username=admin)');
  let res = await fetch('http://localhost:3000/api/search?username=admin');
  let data = await res.json();
  console.log(`Status: ${res.status}`);
  console.log(`Users returned: ${data.users.length}`);
  console.log(`Users: ${data.users.map(u => u.username).join(', ')}\n`);
  
  // Test 2: SQL injection with single quote
  console.log("Test 2: SQL injection (username=admin')");
  res = await fetch("http://localhost:3000/api/search?username=admin'");
  data = await res.json();
  console.log(`Status: ${res.status}`);
  if (res.status === 403) {
    console.log('✅ BLOCKED! Message:', data.message);
  } else {
    console.log('❌ NOT BLOCKED!');
    console.log(`Users returned: ${data.users.length}`);
    console.log(`Warning: ${data.warning || 'none'}`);
  }
  
  process.exit(0);
}

test();
