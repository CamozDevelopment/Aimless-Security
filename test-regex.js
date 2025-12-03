// Test regex patterns
const value = "admin'";

console.log(`Testing value: "${value}"\n`);

const patterns = [
  { name: 'Word + quote at end', pattern: /\w+'\s*$/ },
  { name: 'Quote + OR/AND', pattern: /'\s*(OR|AND|UNION|SELECT|WHERE|FROM|DROP|INSERT|UPDATE|DELETE)\b/i },
  { name: 'Quote + comment', pattern: /'\s*(--|#|\/\*)/ },
  { name: 'Simple quote', pattern: /'/ }
];

patterns.forEach(p => {
  const matches = p.pattern.test(value);
  console.log(`${matches ? '✅' : '❌'} ${p.name}: ${p.pattern}`);
});

console.log('\nThe pattern /\\w+\'\\s*$/ should match "admin\'"');
console.log('Test:', /\w+'\s*$/.test("admin'"));
console.log('Match result:', "admin'".match(/\w+'\s*$/));
