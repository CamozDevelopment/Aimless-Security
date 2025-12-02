// Test the actual injection detector
const { Aimless } = require('./dist/index.js');

const aimless = new Aimless({ rasp: { enabled: true, blockMode: true } });

const testCases = [
  'ＳＥＬＥＣＴ * FROM users',
  "' OR 1=1--",
  'normal text'
];

console.log('Testing Injection Detector:\n');

testCases.forEach(test => {
  console.log(`Input: "${test}"`);
  const result = aimless.validate(test).against(['sql']).result();
  console.log(`Safe: ${result.safe}`);
  console.log(`Threats: ${result.threats.length}`);
  if (result.threats.length > 0) {
    console.log(`  - ${result.threats[0].description}`);
    console.log(`  - Metadata:`, result.threats[0].metadata);
  }
  console.log('');
});
