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

      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request blocked by Aimless Security',
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
