// Quick test of Unicode detection
const pattern = /[\uFF03-\uFF5E]/;
const testString = 'ＳＥＬＥＣＴ * FROM users';

console.log('Test string:', testString);
console.log('Pattern matches:', pattern.test(testString));
console.log('Characters:', testString.split('').map(c => `${c} (U+${c.charCodeAt(0).toString(16).toUpperCase()})`));
