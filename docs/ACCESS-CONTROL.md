# Access Control Quick Reference

## 🎯 What is Access Control?

The **Endpoint Access Control** system lets you define **exactly which APIs** can be executed in your application. Think of it as a bouncer at a club - only the people on the list get in.

## 🚀 Quick Examples

### 1. Only Allow Specific APIs (Allowlist)

```javascript
const aimless = new Aimless({
  rasp: {
    blockMode: true,
    accessControl: {
      mode: 'allowlist',
      defaultAction: 'block',
      allowedEndpoints: [
        { path: '/' },
        { path: '/api/public/*' },
        { path: '/auth/login', methods: ['POST'] }
      ]
    }
  }
});
```

**Result**: Only `/`, `/api/public/*`, and `POST /auth/login` are accessible. Everything else returns 403.

### 2. Block Dangerous Endpoints (Blocklist)

```javascript
accessControl: {
  mode: 'blocklist',
  blockedEndpoints: [
    '/admin/*',
    '/debug/*',
    '/.env'
  ]
}
```

**Result**: Everything is allowed **except** admin routes, debug endpoints, and .env files.

### 3. Protect Sensitive Routes

```javascript
accessControl: {
  mode: 'monitor',
  protectedEndpoints: [
    {
      path: '/api/payments/*',
      maxThreatLevel: 'low',      // Block even low threats
      requireAuth: true,           // Must have auth header
      rateLimit: { 
        maxRequests: 10, 
        windowMs: 60000 
      }
    }
  ]
}
```

**Result**: Payment endpoints get extra security - stricter threat detection, auth required, limited to 10 requests/minute.

## 📋 Configuration Options

### Access Control Modes

| Mode | Behavior |
|------|----------|
| `allowlist` | Only specified endpoints are accessible (strict whitelist) |
| `blocklist` | Everything allowed except blocked endpoints |
| `monitor` | Log access patterns but don't enforce restrictions |

### Endpoint Rules

```typescript
{
  path: string | RegExp,        // Endpoint path or pattern
  methods?: string[],           // Allowed HTTP methods (GET, POST, etc.)
  requireAuth?: boolean,        // Require authentication header
  maxThreatLevel?: 'low' | 'medium' | 'high' | 'critical',
  rateLimit?: {
    maxRequests: number,
    windowMs: number
  }
}
```

### Pattern Matching

| Pattern | Matches | Example |
|---------|---------|---------|
| `/api/users` | Exact match | Only `/api/users` |
| `/api/*` | Wildcard | `/api/users`, `/api/posts`, etc. |
| `/admin/*/settings` | Middle wildcard | `/admin/user/settings` |
| `/^\/api\/v\d+\/.*/` | Regex | `/api/v1/users`, `/api/v2/posts` |

## 🔐 Common Use Cases

### Production API (Strict Security)

```javascript
const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    accessControl: {
      mode: 'allowlist',
      defaultAction: 'block',
      requireAuthHeader: 'X-API-Key',
      
      // Public endpoints
      allowedEndpoints: [
        { path: '/' },
        { path: '/health' },
        { path: '/auth/login', methods: ['POST'] }
      ],
      
      // Extra protection for admin/payments
      protectedEndpoints: [
        {
          path: '/api/admin/*',
          maxThreatLevel: 'low',
          requireAuth: true
        },
        {
          path: '/api/payments/*',
          maxThreatLevel: 'low',
          requireAuth: true,
          rateLimit: { maxRequests: 20, windowMs: 60000 }
        }
      ],
      
      // Explicitly blocked
      blockedEndpoints: [
        '/debug/*',
        '/internal/*',
        /.env/
      ]
    }
  }
});
```

### Development Mode (Monitor Only)

```javascript
const aimless = new Aimless({
  rasp: {
    blockMode: false,  // Don't block, just log
    accessControl: {
      mode: 'monitor'  // Monitor access patterns
    }
  },
  logging: {
    enabled: true,
    level: 'info',
    logFile: './security.log'
  }
});
```

### SaaS Multi-Tenant API

```javascript
accessControl: {
  mode: 'allowlist',
  allowedEndpoints: [
    // Versioned APIs
    { path: /^\/api\/v\d+\/.*/ },
    
    // Tenant-specific endpoints
    { path: /^\/tenants\/[a-z0-9-]+\/.*/, requireAuth: true },
    
    // Public docs
    { path: '/docs/*', methods: ['GET'] }
  ],
  
  protectedEndpoints: [
    {
      path: /^\/tenants\/[a-z0-9-]+\/admin\/.*/,
      maxThreatLevel: 'low',
      requireAuth: true
    }
  ]
}
```

## 🧪 Testing Your Configuration

```javascript
// Check if endpoint is allowed
const result = aimless.rasp.checkEndpointAccess({
  method: 'GET',
  path: '/api/users',
  headers: { 'authorization': 'Bearer token' }
});

console.log(result.allowed);   // true/false
console.log(result.reason);    // Why blocked (if blocked)
console.log(result.matchedRule); // Which rule matched

// Check protected endpoint rules
const rule = aimless.rasp.getProtectionRules({
  method: 'POST',
  path: '/api/payments/charge'
});

if (rule) {
  console.log(rule.maxThreatLevel); // 'low'
  console.log(rule.requireAuth);    // true
}
```

## 📊 Request Flow

```
1. Access Control Check
   ├─ Is endpoint blocked? → 403 Forbidden
   ├─ Is endpoint allowed?
   ├─ Auth header required? → Check header
   └─ Method allowed? → Continue

2. Threat Analysis
   └─ Scan for SQL/XSS/injection threats

3. Protected Endpoint Rules
   ├─ Apply stricter threat levels
   ├─ Per-endpoint rate limiting
   └─ Decide: Allow or Block

4. Response
   └─ Continue to your route handler
```

## 🚨 Security Best Practices

1. **Start with Monitor Mode**
   - Deploy in `monitor` mode first
   - Review logs to understand traffic patterns
   - Switch to `allowlist` or `blocklist` when ready

2. **Use Allowlist for Production**
   - Allowlist mode is most secure (zero-trust)
   - Explicitly define every allowed endpoint
   - Unknown endpoints are blocked by default

3. **Protect Sensitive Routes**
   - Use `protectedEndpoints` for admin, payments, etc.
   - Set `maxThreatLevel: 'low'` for zero tolerance
   - Enable `requireAuth: true`

4. **Combine with blockMode**
   - Set `blockMode: true` to actually block threats
   - `blockMode: false` only logs threats (monitor mode)

5. **Use Wildcards Wisely**
   - `/api/*` is convenient but broad
   - Prefer specific paths when possible
   - Use regex for complex patterns

## 📖 Full Example

See [examples/access-control.js](../examples/access-control.js) for 6 complete configuration examples.

## 🆘 Troubleshooting

**"All my endpoints are blocked!"**
- Check `defaultAction` - set to `'allow'` if using blocklist
- Verify your endpoint paths match exactly (case-sensitive)
- Try `mode: 'monitor'` temporarily to debug

**"Protected endpoint not enforcing strict security"**
- Ensure `blockMode: true` is set
- Check `maxThreatLevel` is set correctly
- Verify the path pattern matches your endpoint

**"Regex patterns not working"**
- Use `/.../` regex literal, not string
- Test your regex pattern separately first
- Remember: patterns are case-sensitive

## 🔗 Related

- [Main README](../README.md) - Full documentation
- [Examples](../examples/) - Complete code examples
- [Vercel Guide](../VERCEL.md) - Serverless deployment
