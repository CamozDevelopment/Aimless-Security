import { Request, Response, NextFunction } from 'express';
import { AimlessConfig, SecurityThreat, WebhookPayload } from '../types';
import { RASP } from '../rasp';
import { Logger } from '../logger';

export interface AimlessRequest extends Request {
  aimless?: {
    threats: SecurityThreat[];
    blocked: boolean;
  };
}

// Helper function to send webhooks
async function sendWebhook(config: AimlessConfig, payload: WebhookPayload, logger: Logger): Promise<void> {
  const webhookConfig = config.rasp?.webhooks;
  
  if (!webhookConfig?.enabled || !webhookConfig.url) {
    return;
  }

  // Check if this event should be sent
  const events = webhookConfig.events || ['all'];
  if (!events.includes('all') && !events.includes(payload.event)) {
    return;
  }

  try {
    // Detect webhook type and format accordingly
    const isDiscord = webhookConfig.url.includes('discord.com');
    const isSlack = webhookConfig.url.includes('slack.com');

    let body: string;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Aimless-Security/1.3.4',
      ...(webhookConfig.customHeaders || {})
    };

    if (isDiscord) {
      // Discord webhook format
      const color = payload.event === 'block' ? 0xdc2626 : 
                    payload.event === 'rateLimit' ? 0xf59e0b : 0xef4444;
      
      const title = payload.event === 'block' 
        ? '🛡️ Security Threat Blocked'
        : payload.event === 'rateLimit'
        ? '⚠️ Rate Limit Exceeded'
        : '🚨 Security Threat Detected';

      body = JSON.stringify({
        embeds: [{
          title,
          color,
          fields: [
            { name: 'IP Address', value: payload.ip || 'unknown', inline: true },
            { name: 'Path', value: payload.path || '/', inline: true },
            { name: 'Method', value: payload.method || 'GET', inline: true },
            { name: 'Timestamp', value: payload.timestamp.toISOString(), inline: true },
            ...(payload.threats && payload.threats.length > 0 ? [{
              name: 'Threats',
              value: payload.threats.map(t => 
                `• ${t.type} (${t.severity}${t.confidence ? ` - ${t.confidence}% confidence` : ''})`
              ).join('\n'),
              inline: false
            }] : [])
          ],
          footer: {
            text: 'Aimless Security v1.3.4'
          },
          timestamp: payload.timestamp.toISOString()
        }]
      });
    } else if (isSlack) {
      // Slack webhook format
      const color = payload.event === 'block' ? '#dc2626' : 
                    payload.event === 'rateLimit' ? '#f59e0b' : '#ef4444';
      
      const emoji = payload.event === 'block' ? '🛡️' : 
                    payload.event === 'rateLimit' ? '⚠️' : '🚨';

      const text = payload.event === 'block' 
        ? `*Security Threat Blocked*`
        : payload.event === 'rateLimit'
        ? `*Rate Limit Exceeded*`
        : `*Security Threat Detected*`;

      body = JSON.stringify({
        attachments: [{
          color,
          title: `${emoji} ${text}`,
          fields: [
            { title: 'IP Address', value: payload.ip || 'unknown', short: true },
            { title: 'Path', value: payload.path || '/', short: true },
            { title: 'Method', value: payload.method || 'GET', short: true },
            { title: 'Timestamp', value: payload.timestamp.toISOString(), short: true },
            ...(payload.threats && payload.threats.length > 0 ? [{
              title: 'Threats',
              value: payload.threats.map(t => 
                `• ${t.type} (${t.severity})`
              ).join('\n'),
              short: false
            }] : [])
          ],
          footer: 'Aimless Security',
          ts: Math.floor(payload.timestamp.getTime() / 1000)
        }]
      });
    } else {
      // Generic webhook
      body = JSON.stringify({
        ...payload,
        payload: webhookConfig.includePayload ? payload.payload : undefined,
        source: 'Aimless Security',
        version: '1.3.4'
      });
    }

    // Log webhook being sent
    logger.info(`🔔 Sending webhook: ${payload.event} to ${webhookConfig.url.substring(0, 50)}...`);

    // Send webhook (fire and forget - don't block request)
    fetch(webhookConfig.url, {
      method: 'POST',
      headers,
      body
    }).then(response => {
      if (response.ok) {
        logger.info(`✅ Webhook delivered successfully (${payload.event})`);
      } else {
        response.text().then(text => {
          logger.warn(`⚠️ Webhook failed: ${response.status} ${response.statusText} - ${text}`);
        });
      }
    }).catch(error => {
      logger.error('Webhook delivery failed:', error);
    });

  } catch (error) {
    logger.error('Webhook error:', error);
  }
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

    // Send webhook for threats (even if not blocking)
    if (threats.length > 0) {
      const webhookPayload: WebhookPayload = {
        event: shouldBlock ? 'block' : 'threat',
        timestamp: new Date(),
        ip,
        path: req.path,
        method: req.method,
        threats,
        userAgent: req.headers['user-agent'] as string,
        reputation: undefined // TODO: Get from anomaly detector
      };
      
      sendWebhook(config, webhookPayload, logger);
    }

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
    
    // Store original send and json methods
    const originalSend = res.send;
    const originalJson = res.json;

    // Override res.send
    res.send = function(body: any): Response {
      // Check if this is an HTML response
      const isHtml = typeof body === 'string' && 
        (body.trim().startsWith('<!DOCTYPE') || body.trim().startsWith('<html'));

      if (isHtml) {
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, minDuration - elapsed);

        const loadingHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Check</title>
  <style>
    #aimless-loading {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100vh;
      background: #1a1a1a;
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    #aimless-loading.fade-out {
      animation: fadeOut 0.5s ease-out forwards;
    }
    .aimless-container {
      text-align: center;
      color: #ffffff;
    }
    .aimless-logo {
      width: 200px;
      height: 200px;
      margin: 0 auto;
      animation: pulse 1.5s ease-in-out infinite;
    }
    .aimless-logo img {
      width: 100%;
      height: 100%;
      object-fit: contain;
    }
    .aimless-message {
      font-size: 24px;
      margin-top: 30px;
      font-weight: 500;
      color: #e0e0e0;
    }
    .aimless-spinner {
      margin: 30px auto;
      width: 50px;
      height: 50px;
      border: 4px solid #333;
      border-top-color: #667eea;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    .aimless-powered {
      margin-top: 30px;
      font-size: 14px;
      color: #888;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.05); opacity: 0.9; }
    }
    @keyframes fadeOut {
      to { opacity: 0; }
    }
    #aimless-content {
      display: none;
    }
  </style>
</head>
<body>
  <div id="aimless-loading">
    <div class="aimless-container">
      <div class="aimless-logo">
        <img src="https://jsdimages.netlify.app/aimless-security-trans-logo.png" alt="Aimless Security" />
      </div>
      <div class="aimless-message">${message}</div>
      <div class="aimless-spinner"></div>
      <div class="aimless-powered">Protected by Aimless Security</div>
    </div>
  </div>
  <div id="aimless-content">${body}</div>
  <script>
    setTimeout(function() {
      var loading = document.getElementById('aimless-loading');
      loading.classList.add('fade-out');
      setTimeout(function() {
        loading.style.display = 'none';
        document.getElementById('aimless-content').style.display = 'block';
      }, 500);
    }, ${delay});
  </script>
</body>
</html>`;
        res.type('html');
        return originalSend.call(res, loadingHTML);
      }

      return originalSend.call(res, body);
    };

    // Also override res.json to pass through normally
    res.json = function(body: any): Response {
      return originalJson.call(res, body);
    };

    next();
  };
}
