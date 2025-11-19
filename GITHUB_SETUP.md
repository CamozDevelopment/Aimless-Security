# GitHub Repository Setup Guide

## Step 1: Create a New Repository on GitHub

1. Go to [GitHub](https://github.com)
2. Click the "+" button in the top right
3. Select "New repository"
4. Fill in the details:
   - **Repository name**: `aimless-security`
   - **Description**: Runtime Application Self-Protection (RASP) and API Fuzzing Engine for Node.js
   - **Visibility**: Public (or Private if you prefer)
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
5. Click "Create repository"

## Step 2: Initialize Git and Push to GitHub

Open PowerShell in the AimlessSDK directory and run:

```powershell
# Initialize git repository
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: Aimless Security v1.0.0"

# Add your GitHub repository as remote (replace yourusername with your GitHub username)
git remote add origin https://github.com/yourusername/aimless-security.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## Step 3: Update Repository Links

After creating your GitHub repo, update these files with your actual username:

### 1. package.json
Replace `yourusername` with your GitHub username:
```json
"repository": {
  "type": "git",
  "url": "https://github.com/YOURUSERNAME/aimless-security.git"
},
"homepage": "https://github.com/YOURUSERNAME/aimless-security#readme",
"bugs": {
  "url": "https://github.com/YOURUSERNAME/aimless-security/issues"
}
```

### 2. README.md
Replace badge URLs with your username:
```markdown
[![GitHub issues](https://img.shields.io/github/issues/YOURUSERNAME/aimless-security.svg?style=flat-square)](https://github.com/YOURUSERNAME/aimless-security/issues)
[![GitHub stars](https://img.shields.io/github/stars/YOURUSERNAME/aimless-security.svg?style=flat-square)](https://github.com/YOURUSERNAME/aimless-security/stargazers)
```

## Step 4: Set Up GitHub Pages (Optional)

To host the documentation site:

1. Go to your repository on GitHub
2. Click "Settings"
3. Scroll to "Pages" in the left sidebar
4. Under "Source", select "main" branch
5. Select "/ (root)" folder
6. Click "Save"
7. Your docs will be available at: `https://yourusername.github.io/aimless-security/docs.html`

## Step 5: Enable GitHub Actions (Optional)

The repository includes CI/CD workflows:

- `.github/workflows/test.yml` - Runs tests on push/PR
- `.github/workflows/npm-publish.yml` - Publishes to NPM on release

To use the NPM publish workflow:
1. Go to repository Settings → Secrets → Actions
2. Add a new secret named `NPM_TOKEN`
3. Get your NPM token from npmjs.com → Access Tokens
4. Paste the token value

## Step 6: Add Topics to Repository

Add these topics to help people find your project:

1. Go to your repository
2. Click the gear icon next to "About"
3. Add topics:
   - `security`
   - `rasp`
   - `api-fuzzing`
   - `nodejs`
   - `typescript`
   - `xss-protection`
   - `csrf-protection`
   - `injection-detection`
   - `vulnerability-scanner`
   - `runtime-protection`

## Step 7: Create a Release

To create your first release:

```powershell
# Tag your current commit
git tag -a v1.0.0 -m "Release version 1.0.0"

# Push the tag
git push origin v1.0.0
```

Then on GitHub:
1. Go to "Releases"
2. Click "Draft a new release"
3. Select tag `v1.0.0`
4. Title: `v1.0.0 - Initial Release`
5. Description: Copy from CHANGELOG.md
6. Click "Publish release"

## Quick Command Reference

```powershell
# Clone your repository
git clone https://github.com/yourusername/aimless-security.git

# Check status
git status

# Add changes
git add .

# Commit changes
git commit -m "Your commit message"

# Push changes
git push

# Create new branch
git checkout -b feature-name

# Switch branches
git checkout main

# Pull latest changes
git pull
```

## Repository Structure

Your GitHub repo will look like this:

```
aimless-security/
├── .github/
│   ├── workflows/          # CI/CD workflows
│   ├── ISSUE_TEMPLATE/     # Issue templates
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── SECURITY.md
│   └── FUNDING.yml
├── src/                    # TypeScript source code
├── dist/                   # Compiled JavaScript (gitignored)
├── examples/               # Usage examples
├── docs.html              # Documentation website
├── README.md              # Main documentation
├── QUICKSTART.md          # Quick start guide
├── CONTRIBUTING.md        # Contribution guidelines
├── CHANGELOG.md           # Version history
├── LICENSE                # MIT License
├── package.json           # NPM package configuration
├── tsconfig.json          # TypeScript configuration
└── .gitignore            # Git ignore rules
```

## Next Steps

1. ✅ Create GitHub repository
2. ✅ Push code to GitHub
3. ✅ Update repository URLs
4. ✅ Add repository topics
5. ✅ Enable GitHub Pages for docs
6. ✅ Create first release
7. ✅ Add repository description
8. ✅ Add social media links
9. ✅ Star your own repo 😄

## Useful GitHub Features

### Enable Discussions
Settings → Features → Discussions (check)

### Add Repository Description
Click the gear icon next to "About" and add:
- Description
- Website (docs URL)
- Topics

### Protect Main Branch
Settings → Branches → Add rule:
- Branch name pattern: `main`
- ✓ Require pull request reviews
- ✓ Require status checks to pass

## Documentation Links

Once your repo is live, you can share:

- **GitHub**: `https://github.com/yourusername/aimless-security`
- **NPM**: `https://www.npmjs.com/package/aimless-security`
- **Docs**: `https://yourusername.github.io/aimless-security/docs.html`
- **Issues**: `https://github.com/yourusername/aimless-security/issues`

## Support

Need help? Check out:
- [GitHub Docs](https://docs.github.com)
- [Git Documentation](https://git-scm.com/doc)
- [NPM Publishing Guide](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)

---

Happy coding! 🚀
