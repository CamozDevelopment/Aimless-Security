import Aimless, { AimlessConfig, FuzzTarget } from 'aimless-security';
import express, { Request, Response, NextFunction } from 'express';

// TypeScript configuration
const config: AimlessConfig = {
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: true,
    anomalyDetection: true,
    trustedOrigins: ['https://yourdomain.com'],
    maxRequestSize: 10 * 1024 * 1024,
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000
    }
  },
  fuzzing: {
    enabled: true,
    maxPayloads: 50,
    timeout: 5000,
    authBypassTests: true,
    rateLimitTests: true,
    graphqlIntrospection: true,
    customPayloads: ['custom-payload-1', 'custom-payload-2']
  },
  logging: {
    enabled: true,
    level: 'info'
  }
};

// Initialize Aimless
const aimless = new Aimless(config);

// Express app
const app = express();
app.use(express.json());

// Apply RASP middleware
app.use(aimless.middleware());

// Type-safe route with threat checking
app.get('/api/users', (req: Request, res: Response) => {
  // Access threat information
  const threats = (req as any).aimless?.threats || [];
  
  if (threats.length > 0) {
    console.log('Detected threats:', threats);
  }

  res.json({ users: [] });
});

// Fuzzing example with TypeScript
async function runFuzzingTests(): Promise<void> {
  const target: FuzzTarget = {
    url: 'https://api.example.com/users',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer token123'
    },
    body: {
      username: 'testuser',
      email: 'test@example.com'
    },
    query: {
      page: '1',
      limit: '10'
    }
  };

  const result = await aimless.fuzz(target);

  console.log(`Fuzzing Results for ${target.method} ${target.url}`);
  console.log(`Tested Payloads: ${result.testedPayloads}`);
  console.log(`Vulnerabilities Found: ${result.vulnerabilities.length}`);
  console.log(`Duration: ${result.duration}ms`);

  // Type-safe vulnerability handling
  result.vulnerabilities.forEach(vuln => {
    console.log(`[${vuln.severity}] ${vuln.type}: ${vuln.description}`);
  });
}

// CSRF token generation
app.get('/csrf-token', (req: Request, res: Response) => {
  const sessionId = req.sessionID || 'default';
  const token = aimless.generateCSRFToken(sessionId);
  
  res.json({ csrfToken: token });
});

// XSS sanitization
app.post('/sanitize', (req: Request, res: Response) => {
  const { input } = req.body;
  const sanitized = aimless.sanitize(input);
  
  res.json({ 
    original: input,
    sanitized 
  });
});

// Manual threat analysis
app.post('/analyze', (req: Request, res: Response) => {
  const threats = aimless.analyze({
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    headers: req.headers as Record<string, string>,
    ip: req.ip
  });

  res.json({ 
    threats,
    safe: threats.length === 0
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`TypeScript server running on port ${PORT}`);
  console.log('Aimless Security enabled');
});

// Export for testing
export { app, aimless };
