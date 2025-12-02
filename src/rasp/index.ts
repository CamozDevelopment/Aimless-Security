import { RASPConfig, SecurityThreat } from '../types';
import { InjectionDetector } from './injection-detector';
import { XSSDetector } from './xss-detector';
import { CSRFDetector } from './csrf-detector';
import { AnomalyDetector } from './anomaly-detector';
import { AdvancedThreatDetector } from './advanced-detector';
import { Logger } from '../logger';

export class RASP {
  private config: Required<RASPConfig>;
  private injectionDetector: InjectionDetector;
  private xssDetector: XSSDetector;
  private csrfDetector: CSRFDetector;
  private anomalyDetector: AnomalyDetector;
  private advancedDetector: AdvancedThreatDetector;
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
    this.advancedDetector = new AdvancedThreatDetector();
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

    try {
      // Injection detection - only if data exists
      if (this.config.injectionProtection) {
        if (request.query && typeof request.query === 'object') {
          const queryThreats = this.injectionDetector.detect(request.query, 'query');
          threats.push(...queryThreats);
        }
        if (request.body && typeof request.body === 'object') {
          const bodyThreats = this.injectionDetector.detect(request.body, 'body');
          threats.push(...bodyThreats);
        }
      }

      // XSS detection - only if data exists
      if (this.config.xssProtection) {
        if (request.query && typeof request.query === 'object') {
          const queryXSS = this.xssDetector.detect(request.query, 'query');
          threats.push(...queryXSS);
        }
        if (request.body && typeof request.body === 'object') {
          const bodyXSS = this.xssDetector.detect(request.body, 'body');
          threats.push(...bodyXSS);
        }
      }

      // Advanced threat detection (LDAP, Template Injection, etc.) - with safety check
      if (request.body) {
        const advancedThreats = this.advancedDetector.detectAll(
          request.body, 
          request.path?.includes('graphql') ? 'graphql' : undefined
        );
        threats.push(...advancedThreats);
      }
    } catch (detectionError) {
      // Log error but continue - don't let detection errors break the request
      this.logger.error('Error during threat detection:', detectionError);
    }

    try {
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

    } catch (csrfError) {
      this.logger.error('Error during CSRF detection:', csrfError);
    }

    try {
      // Anomaly detection
      if (this.config.anomalyDetection && request.ip) {
        const userAgent = this.getHeader(request.headers || {}, 'user-agent');
        let bodySize = 0;
        try {
          bodySize = request.body ? JSON.stringify(request.body).length : 0;
        } catch {
          bodySize = 0; // Circular reference or other JSON error
        }
        
        const anomalies = this.anomalyDetector.detect(
          request.ip,
          request.method,
          request.path,
          userAgent,
          bodySize
        );
        
        threats.push(...anomalies);
      }
    } catch (anomalyError) {
      this.logger.error('Error during anomaly detection:', anomalyError);
    }

    // Log threats safely
    try {
      threats.forEach(threat => this.logger.threat(threat));
    } catch (logError) {
      // Even logging shouldn't break the flow
      console.error('Failed to log threats:', logError);
    }

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
   * Detect LDAP injection
   */
  detectLDAPInjection(input: string): SecurityThreat | null {
    return this.advancedDetector.detectLDAPInjection(input);
  }

  /**
   * Detect template injection (SSTI)
   */
  detectTemplateInjection(input: string): SecurityThreat | null {
    return this.advancedDetector.detectTemplateInjection(input);
  }

  /**
   * Validate file upload security
   */
  validateFileUpload(filename: string, content?: string, mimeType?: string): SecurityThreat | null {
    return this.advancedDetector.validateFileUpload(filename, content, mimeType);
  }

  /**
   * Analyze JWT token security
   */
  analyzeJWT(token: string): SecurityThreat | null {
    return this.advancedDetector.analyzeJWT(token);
  }

  /**
   * Detect GraphQL attacks
   */
  detectGraphQLAttack(query: string): SecurityThreat | null {
    return this.advancedDetector.detectGraphQLAttack(query);
  }

  /**
   * Detect prototype pollution
   */
  detectPrototypePollution(input: any): SecurityThreat | null {
    return this.advancedDetector.detectPrototypePollution(input);
  }

  /**
   * Detect deserialization attacks
   */
  detectDeserialization(input: string): SecurityThreat | null {
    return this.advancedDetector.detectDeserialization(input);
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

  getAdvancedDetector(): AdvancedThreatDetector {
    return this.advancedDetector;
  }

  private getHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
    const value = headers[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
  }
}
