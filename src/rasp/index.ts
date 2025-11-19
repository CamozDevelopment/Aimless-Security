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
