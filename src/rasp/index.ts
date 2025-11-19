import { RASPConfig, SecurityThreat } from '../types';
import { InjectionDetector } from './injection-detector';
import { XSSDetector } from './xss-detector';
import { CSRFDetector } from './csrf-detector';
import { AnomalyDetector } from './anomaly-detector';
import { Logger } from '../logger';

export class RASP {
  private config: Required<RASPConfig>;
  private injectionDetector: InjectionDetector;
  private xssDetector: XSSDetector;
  private csrfDetector: CSRFDetector;
  private anomalyDetector: AnomalyDetector;
  private logger: Logger;

  constructor(config: RASPConfig = {}, logger: Logger) {
    this.config = {
      enabled: true,
      injectionProtection: true,
      xssProtection: true,
      csrfProtection: false, // Disabled by default to avoid false positives
      anomalyDetection: false, // Disabled by default to avoid false positives
      blockMode: false, // Detection mode by default - safer for production
      accessControl: {
        mode: 'monitor', // Default to monitor mode
        defaultAction: 'allow',
        ...config.accessControl
      },
      trustedOrigins: [],
      maxRequestSize: 10 * 1024 * 1024, // 10MB
      rateLimiting: {
        enabled: false, // Disabled by default
        maxRequests: 100,
        windowMs: 60000
      },
      ...config
    };

    this.logger = logger;
    this.injectionDetector = new InjectionDetector();
    this.xssDetector = new XSSDetector();
    this.csrfDetector = new CSRFDetector(this.config.trustedOrigins);
    this.anomalyDetector = new AnomalyDetector();
  }

  analyze(request: {
    method: string;
    path: string;
    query?: any;
    body?: any;
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  }): SecurityThreat[] {
    if (!this.config.enabled) return [];

    const threats: SecurityThreat[] = [];

    // Injection detection
    if (this.config.injectionProtection) {
      const queryThreats = this.injectionDetector.detect(request.query, 'query');
      const bodyThreats = this.injectionDetector.detect(request.body, 'body');
      threats.push(...queryThreats, ...bodyThreats);
    }

    // XSS detection
    if (this.config.xssProtection) {
      const queryXSS = this.xssDetector.detect(request.query, 'query');
      const bodyXSS = this.xssDetector.detect(request.body, 'body');
      threats.push(...queryXSS, ...bodyXSS);
    }

    // CSRF detection
    if (this.config.csrfProtection && request.headers) {
      const origin = this.getHeader(request.headers, 'origin');
      const referer = this.getHeader(request.headers, 'referer');
      const csrfToken = this.getHeader(request.headers, 'x-csrf-token');
      const sessionId = this.getHeader(request.headers, 'cookie')?.split('sessionId=')[1]?.split(';')[0];

      const csrfThreat = this.csrfDetector.detect(
        request.method,
        origin,
        referer,
        csrfToken,
        sessionId
      );
      
      if (csrfThreat) threats.push(csrfThreat);
    }

    // Anomaly detection
    if (this.config.anomalyDetection && request.ip) {
      const userAgent = this.getHeader(request.headers || {}, 'user-agent');
      const bodySize = request.body ? JSON.stringify(request.body).length : 0;
      
      const anomalies = this.anomalyDetector.detect(
        request.ip,
        request.method,
        request.path,
        userAgent,
        bodySize
      );
      
      threats.push(...anomalies);
    }

    // Log threats
    threats.forEach(threat => this.logger.threat(threat));

    return threats;
  }

  shouldBlock(threats: SecurityThreat[]): boolean {
    if (!this.config.blockMode) return false;
    return threats.some(t => t.blocked && ['high', 'critical'].includes(t.severity));
  }

  /**
   * Check if endpoint is allowed based on access control rules
   */
  checkEndpointAccess(request: {
    method: string;
    path: string;
    headers?: Record<string, string | string[] | undefined>;
  }): { allowed: boolean; reason?: string; matchedRule?: any } {
    const ac = this.config.accessControl;
    if (!ac || ac.mode === 'monitor') {
      return { allowed: true }; // Monitor mode - always allow, just log
    }

    const { method, path, headers } = request;

    // Check if endpoint is explicitly blocked
    if (ac.blockedEndpoints?.length) {
      const blocked = ac.blockedEndpoints.some(pattern => 
        this.matchesPattern(path, pattern)
      );
      if (blocked) {
        return { allowed: false, reason: 'Endpoint is blocked' };
      }
    }

    // Check authentication requirement
    if (ac.requireAuthHeader && headers) {
      const authHeader = headers[ac.requireAuthHeader.toLowerCase()];
      if (!authHeader) {
        return { allowed: false, reason: `Missing required header: ${ac.requireAuthHeader}` };
      }
    }

    // ALLOWLIST mode - only explicitly allowed endpoints are permitted
    if (ac.mode === 'allowlist') {
      if (!ac.allowedEndpoints?.length) {
        // No allowed endpoints defined, use defaultAction
        const allowed = ac.defaultAction === 'allow';
        return { 
          allowed, 
          reason: allowed ? undefined : 'Endpoint not in allowlist'
        };
      }

      const matchedRule = ac.allowedEndpoints.find(rule => {
        const pathMatches = this.matchesPattern(path, rule.path);
        const methodMatches = !rule.methods || rule.methods.includes(method);
        return pathMatches && methodMatches;
      });

      if (!matchedRule) {
        return { allowed: false, reason: 'Endpoint not in allowlist', matchedRule };
      }

      // Check method-specific rules
      if (matchedRule.methods && !matchedRule.methods.includes(method)) {
        return { 
          allowed: false, 
          reason: `Method ${method} not allowed for this endpoint`,
          matchedRule 
        };
      }

      // Check auth requirement for this specific endpoint
      if (matchedRule.requireAuth && headers) {
        const authHeader = headers['authorization'] || headers['x-api-key'];
        if (!authHeader) {
          return { 
            allowed: false, 
            reason: 'Authentication required for this endpoint',
            matchedRule 
          };
        }
      }

      return { allowed: true, matchedRule };
    }

    // BLOCKLIST mode - all endpoints allowed except explicitly blocked
    if (ac.mode === 'blocklist') {
      return { allowed: true }; // Already checked blockedEndpoints above
    }

    // Default action for unmatched
    const allowed = ac.defaultAction === 'allow';
    return { 
      allowed, 
      reason: allowed ? undefined : 'No matching rule, default is block'
    };
  }

  /**
   * Check if endpoint has extra protection rules
   */
  getProtectionRules(request: { method: string; path: string }) {
    const ac = this.config.accessControl;
    if (!ac?.protectedEndpoints?.length) return null;

    return ac.protectedEndpoints.find(rule => {
      const pathMatches = this.matchesPattern(request.path, rule.path);
      const methodMatches = !rule.methods || rule.methods.includes(request.method);
      return pathMatches && methodMatches;
    });
  }

  /**
   * Match path against string or regex pattern
   */
  private matchesPattern(path: string, pattern: string | RegExp): boolean {
    if (typeof pattern === 'string') {
      // Support wildcards: /api/* matches /api/users, /api/posts, etc.
      if (pattern.includes('*')) {
        const regexPattern = pattern.replace(/\*/g, '.*').replace(/\//g, '\\/');
        return new RegExp(`^${regexPattern}$`).test(path);
      }
      return path === pattern;
    }
    return pattern.test(path);
  }

  generateCSRFToken(sessionId: string): string {
    return this.csrfDetector.generateToken(sessionId);
  }

  sanitizeOutput(output: string): string {
    return this.xssDetector.sanitize(output);
  }

  /**
   * Detect injections (SQL, NoSQL, Command, Path Traversal, etc.)
   */
  detectInjections(input: any, context?: string): SecurityThreat[] {
    return this.injectionDetector.detect(input, context);
  }

  /**
   * Get direct access to detectors for advanced use cases
   */
  getInjectionDetector(): InjectionDetector {
    return this.injectionDetector;
  }

  getXSSDetector(): XSSDetector {
    return this.xssDetector;
  }

  getCSRFDetector(): CSRFDetector {
    return this.csrfDetector;
  }

  getAnomalyDetector(): AnomalyDetector {
    return this.anomalyDetector;
  }

  private getHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
    const value = headers[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
  }
}
