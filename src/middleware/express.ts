import { Request, Response, NextFunction } from 'express';
import { AimlessConfig, SecurityThreat } from '../types';
import { RASP } from '../rasp';
import { Logger } from '../logger';

export interface AimlessRequest extends Request {
  aimless?: {
    threats: SecurityThreat[];
    blocked: boolean;
  };
}

export function createMiddleware(config: AimlessConfig = {}) {
  const logger = new Logger(config.logging);
  const rasp = new RASP(config.rasp, logger);

  return (req: AimlessRequest, res: Response, next: NextFunction) => {
    try {
      // Get client IP with safety checks
      const ip = (req.headers?.['x-forwarded-for'] as string)?.split(',')[0]?.trim() || 
                 (req.headers?.['x-real-ip'] as string) ||
                 req.socket?.remoteAddress ||
                 req.ip ||
                 'unknown';

    // Step 1: Check endpoint access control
    const accessCheck = rasp.checkEndpointAccess({
      method: req.method,
      path: req.path,
      headers: req.headers as Record<string, string>
    });

    if (!accessCheck.allowed) {
      logger.warn('Request blocked by access control', {
        ip,
        path: req.path,
        method: req.method,
        reason: accessCheck.reason
      });

      return res.status(403).json({
        error: 'Forbidden',
        message: accessCheck.reason || 'Access denied',
        timestamp: new Date().toISOString()
      });
    }

    // Step 2: Analyze request for security threats
    // Only analyze if query/body exist and are objects
    const threats = rasp.analyze({
      method: req.method,
      path: req.path || req.url || '/',
      query: req.query && typeof req.query === 'object' ? req.query : undefined,
      body: req.body && typeof req.body === 'object' ? req.body : undefined,
      headers: (req.headers || {}) as Record<string, string>,
      ip
    });

    // Step 3: Check for protected endpoint rules
    const protectionRule = rasp.getProtectionRules({
      method: req.method,
      path: req.path
    });

    let shouldBlock = rasp.shouldBlock(threats);

    // Apply stricter rules for protected endpoints
    if (protectionRule && protectionRule.maxThreatLevel) {
      const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 };
      const maxLevel = severityLevels[protectionRule.maxThreatLevel];
      
      const hasExcessiveThreat = threats.some(t => 
        severityLevels[t.severity] > maxLevel
      );

      if (hasExcessiveThreat) {
        shouldBlock = true;
        logger.warn('Protected endpoint exceeded threat level', {
          ip,
          path: req.path,
          maxAllowed: protectionRule.maxThreatLevel,
          threats: threats.map(t => ({ type: t.type, severity: t.severity }))
        });
      }
    }

    // Attach threat info to request
    req.aimless = {
      threats,
      blocked: shouldBlock
    };

    // Block request if necessary
    if (shouldBlock) {
      logger.error('Request blocked due to security threats', {
        ip,
        path: req.path,
        method: req.method,
        threats: threats.length
      });

      const baseMessage = 'Request blocked by Aimless Security';
      const fullMessage = config.rasp?.customBlockMessage 
        ? `${baseMessage}. ${config.rasp.customBlockMessage}`
        : baseMessage;

      return res.status(403).json({
        error: 'Forbidden',
        message: fullMessage,
        details: config.rasp?.blockMode ? 'Security threat detected' : undefined,
        timestamp: new Date().toISOString()
      });
    }

    // Continue to next middleware
    next();
    } catch (error) {
      // Log error but don't break the application
      logger.error('Aimless middleware error:', error);
      
      // In production, fail open (allow request) rather than fail closed
      // This prevents the security middleware from breaking the app
      if (config.rasp?.blockMode === false || !config.rasp?.blockMode) {
        // Allow request to continue
        next();
      } else {
        // Only block if explicitly in block mode and configured to fail closed
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Security check failed',
          timestamp: new Date().toISOString()
        });
      }
    }
  };
}

export function csrfProtection(config: AimlessConfig = {}) {
  const logger = new Logger(config.logging);
  const rasp = new RASP(config.rasp, logger);

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Add CSRF token to response locals
      const sessionId = (req as any).session?.id || (req as any).sessionID || 'default';
      const csrfToken = rasp.generateCSRFToken(sessionId);

      // Safely set locals and header
      if (res.locals) {
        res.locals.csrfToken = csrfToken;
      }
      
      if (!res.headersSent) {
        res.setHeader('X-CSRF-Token', csrfToken);
      }

      next();
    } catch (error) {
      logger.error('CSRF middleware error:', error);
      // Fail open - continue without CSRF token rather than breaking the app
      next();
    }
  };
}

/**
 * Loading screen middleware - shows "Checking security..." screen
 * Place this BEFORE the main Aimless middleware
 */
export function loadingScreen(config: AimlessConfig = {}) {
  const loadingConfig = config.rasp?.loadingScreen;
  
  // If loading screen is disabled, return no-op middleware
  if (!loadingConfig?.enabled) {
    return (req: Request, res: Response, next: NextFunction) => next();
  }

  const message = loadingConfig.message || 'Checking security...';
  const minDuration = loadingConfig.minDuration || 500;

  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    
    // Intercept HTML responses to inject loading screen
    const originalSend = res.send.bind(res);
    let sent = false;

    res.send = function(body: any) {
      if (sent) return originalSend(body);
      sent = true;

      // Only inject loading screen for HTML responses
      const contentType = res.getHeader('content-type');
      if (contentType && contentType.toString().includes('text/html')) {
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, minDuration - elapsed);

        // Inject loading screen HTML
        const loadingHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Check</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      overflow: hidden;
    }
    .loading-container {
      text-align: center;
      color: white;
    }
    .shield {
      font-size: 64px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    .message {
      font-size: 24px;
      margin-top: 20px;
      font-weight: 500;
    }
    .spinner {
      margin: 30px auto;
      width: 50px;
      height: 50px;
      border: 4px solid rgba(255, 255, 255, 0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    .powered-by {
      margin-top: 30px;
      font-size: 14px;
      opacity: 0.8;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.1); opacity: 0.8; }
    }
    .fade-out {
      animation: fadeOut 0.5s ease-out forwards;
    }
    @keyframes fadeOut {
      to { opacity: 0; }
    }
  </style>
</head>
<body>
  <div class="loading-container" id="loadingScreen">
    <div class="shield">🛡️</div>
    <div class="message">${message}</div>
    <div class="spinner"></div>
    <div class="powered-by">Protected by Aimless Security</div>
  </div>
  <div id="content" style="display: none;">${body}</div>
  <script>
    setTimeout(function() {
      document.getElementById('loadingScreen').classList.add('fade-out');
      setTimeout(function() {
        document.getElementById('loadingScreen').style.display = 'none';
        document.getElementById('content').style.display = 'block';
        document.body.style.background = '';
        document.body.style.overflow = '';
      }, 500);
    }, ${delay});
  </script>
</body>
</html>`;
        return originalSend(loadingHTML);
      }

      return originalSend(body);
    } as any;

    next();
  };
}
