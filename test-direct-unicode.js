// Direct test of the injection detector with the exact value
const { InjectionDetector } = require('./dist/rasp/injection-detector.js');

const detector = new InjectionDetector();
const testValue = 'ＳＥＬＥＣＴ * FROM users';

console.log('Testing value:', testValue);
console.log('Character codes:', testValue.split('').map(c => c.charCodeAt(0).toString(16)));

const threats = detector.detect(testValue, 'body');
console.log('\nThreats detected:', threats.length);
threats.forEach(t => {
  console.log('  -', t.description);
  console.log('    Metadata:', t.metadata);
});
