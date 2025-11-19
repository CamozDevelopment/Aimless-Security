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
    // Get client IP
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || 
               (req.headers['x-real-ip'] as string) ||
               req.socket.remoteAddress ||
               'unknown';

    // Analyze request
    const threats = rasp.analyze({
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.body,
      headers: req.headers as Record<string, string>,
      ip
    });

    // Attach threat info to request
    req.aimless = {
      threats,
      blocked: rasp.shouldBlock(threats)
    };

    // Block request if necessary
    if (req.aimless.blocked) {
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
  };
}

export function csrfProtection(config: AimlessConfig = {}) {
  const logger = new Logger(config.logging);
  const rasp = new RASP(config.rasp, logger);

  return (req: Request, res: Response, next: NextFunction) => {
    // Add CSRF token to response locals
    const sessionId = (req as any).session?.id || (req as any).sessionID || 'default';
    const csrfToken = rasp.generateCSRFToken(sessionId);

    res.locals.csrfToken = csrfToken;
    res.setHeader('X-CSRF-Token', csrfToken);

    next();
  };
}
