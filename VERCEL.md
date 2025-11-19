# Aimless Security - Vercel/Serverless Deployment Guide

## ✅ Vercel Compatibility (v1.1.2+)

Aimless Security v1.1.2 is fully compatible with Vercel and all serverless platforms.

## Quick Setup for Vercel

### 1. Install

```bash
npm install aimless-security
```

### 2. Add to next.config.js

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['aimless-security']
  }
}

module.exports = nextConfig
```

### 3. Use in API Routes (REQUIRED: Node.js Runtime)

```typescript
// app/api/validate/route.ts
export const runtime = 'nodejs'; // ← CRITICAL for Vercel

import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false, // Detect only, don't auto-block
  }
});

export async function POST(request: Request) {
  const body = await request.json();
  
  const result = aimless.validate(body.input)
    .against(['sql', 'xss'])
    .sanitize()
    .result();
  
  if (!result.safe) {
    return Response.json({
      error: 'Invalid input',
      threats: result.threats
    }, { status: 400 });
  }
  
  return Response.json({ success: true });
}
```

## ⚠️ Important: DO NOT Use in Edge Runtime

Edge Runtime does not support Node.js crypto module. Always use:

```typescript
export const runtime = 'nodejs'; // NOT 'edge'
```

## Best Practices for Vercel

### 1. **Validate Specific Routes Only**

Don't validate ALL routes - only those with user input:

```typescript
// ✅ Validate these:
// POST /api/auth/login
// POST /api/comments
// POST /api/search

// ❌ Don't validate these:
// GET /api/status
// GET /api/products
// GET /api/user
```

### 2. **Use Detection Mode First**

```typescript
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false, // Detection only
  }
});

// Log threats instead of blocking
if (!result.safe) {
  console.log('Threat detected:', result.threats);
  // Decide what to do
}
```

### 3. **Wrap in Try-Catch**

```typescript
export async function POST(request: Request) {
  try {
    const { Aimless } = await import('aimless-security');
    const aimless = new Aimless();
    
    // Your validation logic
  } catch (error) {
    console.error('Aimless Security error:', error);
    // Fallback: allow request if security check fails
  }
}
```

### 4. **Validate Specific Fields**

```typescript
function validateUserInput(body: any) {
  const fieldsToCheck = ['search', 'comment', 'message'];
  
  for (const field of fieldsToCheck) {
    if (body[field]) {
      const result = aimless.validate(body[field])
        .against(['sql', 'xss'])
        .result();
      
      if (!result.safe) {
        return { safe: false, field, threats: result.threats };
      }
    }
  }
  
  return { safe: true };
}
```

## Common Issues & Solutions

### Issue: "crypto is not defined"
**Solution:** Add `export const runtime = 'nodejs';` to your route

### Issue: "Cannot find module"
**Solution:** Add `serverComponentsExternalPackages: ['aimless-security']` to next.config.js

### Issue: Works locally, fails on Vercel
**Solution:** Check you're not using middleware with Edge Runtime

### Issue: All requests return 500
**Solution:** Set `blockMode: false` and validate specific routes only

## Environment Variables

```env
# .env.local
NODE_ENV=production
```

## Deployment Checklist

- [ ] `export const runtime = 'nodejs';` in all API routes using Aimless
- [ ] `serverComponentsExternalPackages` in next.config.js
- [ ] `blockMode: false` for initial deployment
- [ ] Try-catch around Aimless initialization
- [ ] Validate only POST/PUT routes with user input
- [ ] Test locally before deploying

## Example: Complete Protected API Route

```typescript
// app/api/contact/route.ts
export const runtime = 'nodejs';

import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false
  }
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { name, email, message } = body;
    
    // Validate message field
    const result = aimless.validate(message)
      .against(['xss', 'sql'])
      .sanitize()
      .result();
    
    if (!result.safe) {
      console.warn('Blocked malicious input:', result.threats);
      return Response.json({
        error: 'Invalid input detected'
      }, { status: 400 });
    }
    
    // Process with sanitized data
    await saveToDatabase({
      name,
      email,
      message: result.sanitized
    });
    
    return Response.json({ success: true });
    
  } catch (error) {
    console.error('API error:', error);
    return Response.json({
      error: 'Internal server error'
    }, { status: 500 });
  }
}
```

## Support

- GitHub Issues: https://github.com/CamozDevelopment/Aimless-Security/issues
- NPM: https://www.npmjs.com/package/aimless-security

## Version History

- **v1.1.2** - Full Vercel/serverless compatibility
- **v1.1.1** - Enhanced detection patterns
- **v1.1.0** - Major feature release
- **v1.0.x** - Initial release
