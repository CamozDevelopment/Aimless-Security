# Quick Installation Test

Test that aimless-security installs correctly from GitHub.

## Test in a new project:

```bash
# Create test directory
mkdir test-aimless-security
cd test-aimless-security
npm init -y

# Install from GitHub
npm install CamozDevelopment/Aimless-Security

# Or install specific version
npm install CamozDevelopment/Aimless-Security#v1.3.6
```

## Test the installation:

Create `test.js`:
```javascript
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true
  }
});

console.log('✅ Aimless SDK loaded successfully!');

// Test SQL injection detection
const result = aimless.validate("' OR '1'='1")
  .against(['sql'])
  .result();

console.log('SQL Injection Test:', result.safe ? '❌ Failed' : '✅ Detected');
console.log('Confidence:', result.threats[0]?.confidence);
```

Run:
```bash
node test.js
```

Expected output:
```
✅ Aimless SDK loaded successfully!
SQL Injection Test: ✅ Detected
Confidence: 60%
```

## Users can now install with:

```bash
npm install CamozDevelopment/Aimless-Security
```

**No NPM publishing required!** ✅
