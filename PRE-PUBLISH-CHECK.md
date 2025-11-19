# Pre-Publish Checklist

Before publishing to NPM, ensure all these checks pass:

## 1. Build Check
```bash
npm run build
```
✅ TypeScript compilation must succeed with no errors

## 2. Test Suite
```bash
npm test
```
✅ All 20 serverless compatibility tests must pass

## 3. Package Import Verification
```bash
npm run verify
```
✅ Package must import successfully from dist/

## 4. Manual Smoke Tests
```bash
node -e "const { Aimless } = require('./dist/index.js'); const a = new Aimless(); console.log('Safe:', a.isSafe('test'));"
```
✅ Should output: `Safe: true`

```bash
node -e "const { Aimless } = require('./dist/index.js'); const a = new Aimless(); console.log('Safe:', a.isSafe(\"' OR 1=1--\"));"
```
✅ Should output: `Safe: false`

## 5. File Structure Check
```bash
ls dist/
```
✅ Must contain:
- index.js
- index.d.ts
- All module folders (rasp/, middleware/, utils/, etc.)

## 6. Package Size Check
```bash
npm pack --dry-run
```
✅ Package size should be under 200KB
✅ No src/ files should be included
✅ No test files should be included
✅ Only dist/, README.md, LICENSE, and package.json

## 7. Version Check
- Current version in package.json: **1.1.2**
- Ensure CHANGELOG.md is updated
- Ensure README.md mentions latest version

## 8. Dependencies Check
```bash
npm ls
```
✅ No missing dependencies
✅ Express is in peerDependencies (optional)

## 9. Node.js Version Compatibility
Test on multiple Node versions:
```bash
node --version  # Should be 16+, 18+, or 20+
```

## 10. Git Status
```bash
git status
```
✅ All changes committed
✅ Working directory clean

## Auto-Run Checklist
The `prepublishOnly` script runs automatically before `npm publish` and executes:
1. `npm run build` - Compiles TypeScript
2. `npm test` - Runs all 20 compatibility tests

If any test fails, the publish will be aborted automatically.

## Final Manual Check
Before running `npm publish`:

1. Double-check version number is correct: `1.1.2`
2. Review CHANGELOG.md for completeness
3. Ensure you're logged into NPM: `npm whoami`
4. Verify you have publish rights to `aimless-security`

## Publish Command
```bash
npm publish
```

## Post-Publish Verification
After successful publish:

1. Wait 1-2 minutes for NPM to propagate
2. Test installation in a fresh directory:
```bash
mkdir test-install && cd test-install
npm init -y
npm install aimless-security@1.1.2
node -e "const { Aimless } = require('aimless-security'); console.log('✅ Package works!');"
```

3. Check NPM page: https://www.npmjs.com/package/aimless-security
4. Verify version shows `1.1.2`
5. Verify badges are displaying correctly

## Troubleshooting

### If tests fail:
1. Review test-serverless.js output
2. Check which specific test failed
3. Fix the issue
4. Re-run `npm test`

### If build fails:
1. Check TypeScript errors
2. Ensure all imports are correct
3. Verify tsconfig.json is valid
4. Re-run `npm run build`

### If publish fails:
1. Check NPM authentication: `npm login`
2. Verify package name is available
3. Ensure version is not already published
4. Check network connection

## Success Criteria

All checks must pass ✅ before publishing:
- [x] Build succeeds
- [x] All 20 tests pass
- [x] Package imports successfully
- [x] Manual smoke tests work
- [x] File structure is correct
- [x] Package size is reasonable
- [x] Version is correct
- [x] Dependencies are valid
- [x] Node.js compatibility verified
- [x] Git working directory is clean
