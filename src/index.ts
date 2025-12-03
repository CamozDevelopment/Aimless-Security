import { AimlessConfig } from './types';
import { RASP } from './rasp';
import { FuzzingEngine, FuzzTarget } from './fuzzing';
import { Logger } from './logger';
import { createMiddleware, csrfProtection, loadingScreen } from './middleware/express';

export class Aimless {
  private rasp: RASP;
  private fuzzer: FuzzingEngine;
  private logger: Logger;
  private config: AimlessConfig;

  constructor(config: AimlessConfig = {}) {
    this.config = config;
    this.logger = new Logger(config.logging);
    this.rasp = new RASP(config.rasp, this.logger);
    this.fuzzer = new FuzzingEngine(config.fuzzing, this.logger);
  }

  /**
   * Get Express middleware for RASP protection
   */
  middleware() {
    return createMiddleware(this.config);
  }

  /**
   * Get CSRF protection middleware
   */
  csrf() {
    return csrfProtection(this.config);
  }

  /**
   * Get loading screen middleware (place BEFORE main middleware)
   */
  loading() {
    return loadingScreen(this.config);
  }

  /**
   * Analyze a request for security threats
   */
  analyze(request: {
    method: string;
    path: string;
    query?: any;
    body?: any;
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  }) {
    return this.rasp.analyze(request);
  }

  /**
   * Generate a CSRF token for a session
   */
  generateCSRFToken(sessionId: string): string {
    return this.rasp.generateCSRFToken(sessionId);
  }

  /**
   * Sanitize output to prevent XSS
   */
  sanitize(output: string): string {
    return this.rasp.sanitizeOutput(output);
  }

  /**
   * Fuzz test an API endpoint
   */
  async fuzz(target: FuzzTarget) {
    return this.fuzzer.fuzz(target);
  }

  /**
   * Get the logger instance
   */
  getLogger(): Logger {
    return this.logger;
  }

  /**
   * Quick validation helper - check if input is safe
   */
  isSafe(input: any, context?: string): boolean {
    const threats = this.rasp.detectInjections(input, context);
    return threats.length === 0;
  }

  /**
   * Context-aware sanitization with multiple output contexts
   */
  sanitizeFor(input: string, context: 'html' | 'attribute' | 'javascript' | 'css' | 'url' = 'html'): string {
    // Use XSS detector's enhanced sanitization
    const xssDetector = (this.rasp as any).xssDetector;
    if (xssDetector && typeof xssDetector.sanitize === 'function') {
      return xssDetector.sanitize(input, context);
    }
    return this.rasp.sanitizeOutput(input);
  }

  /**
   * Validate and sanitize in one call
   */
  validateAndSanitize(input: string, context?: string): { safe: boolean; sanitized: string; threats: any[] } {
    const threats = this.rasp.detectInjections(input, context);
    const safe = threats.length === 0;
    const sanitized = this.rasp.sanitizeOutput(input);
    
    return { safe, sanitized, threats };
  }

  /**
   * Get IP reputation score (0-100)
   */
  getIPReputation(ip: string): number {
    const anomalyDetector = (this.rasp as any).anomalyDetector;
    if (anomalyDetector && typeof anomalyDetector.getReputationScore === 'function') {
      return anomalyDetector.getReputationScore(ip);
    }
    return 100;
  }

  /**
   * Block or unblock an IP address
   */
  setIPBlocked(ip: string, blocked: boolean): void {
    const anomalyDetector = (this.rasp as any).anomalyDetector;
    if (anomalyDetector && typeof anomalyDetector.setIPBlocked === 'function') {
      anomalyDetector.setIPBlocked(ip, blocked);
    }
  }

  /**
   * Get security statistics
   */
  getStats(): {
    rasp: any;
    fuzzing?: any;
  } {
    const anomalyDetector = (this.rasp as any).anomalyDetector;
    const stats: any = {
      rasp: {}
    };

    if (anomalyDetector && typeof anomalyDetector.getStats === 'function') {
      stats.rasp = anomalyDetector.getStats();
    }

    return stats;
  }

  /**
   * Get security analytics (v1.3.4 feature)
   */
  getAnalytics(): any {
    // Placeholder - returns basic stats for now
    // In a full implementation, this would use SecurityAnalyticsEngine
    return {
      totalRequests: 0,
      threatsDetected: 0,
      threatsBlocked: 0,
      topAttackTypes: [],
      topAttackIPs: [],
      requestsByHour: [],
      averageResponseTime: 0,
      uptime: Date.now() - (this as any).startTime || 0
    };
  }

  /**
   * Get analytics summary text (v1.3.4 feature)
   */
  getAnalyticsSummary(): string {
    const analytics = this.getAnalytics();
    return `
📊 Security Analytics Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Requests: ${analytics.totalRequests.toLocaleString()}
Threats Detected: ${analytics.threatsDetected.toLocaleString()}
Threats Blocked: ${analytics.threatsBlocked.toLocaleString()}
Average Response Time: ${analytics.averageResponseTime.toFixed(2)}ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `.trim();
  }

  /**
   * Clear security history (for testing or privacy)
   */
  clearHistory(ip?: string): void {
    const anomalyDetector = (this.rasp as any).anomalyDetector;
    if (anomalyDetector && typeof anomalyDetector.clearHistory === 'function') {
      anomalyDetector.clearHistory(ip);
    }
  }

  /**
   * Quick-start method: protect an Express app with sensible defaults
   */
  static quickProtect(trustedOrigins?: string[]) {
    const aimless = new Aimless({
      rasp: {
        enabled: true,
        blockMode: true,
        trustedOrigins: trustedOrigins || []
      },
      logging: {
        level: 'info'
      }
    });

    return {
      middleware: aimless.middleware(),
      csrf: aimless.csrf(),
      aimless
    };
  }

  /**
   * Create a validation chain for fluent API
   */
  validate(input: any) {
    const threats: any[] = [];
    let sanitized = input;

    return {
      against: (checks: ('sql' | 'nosql' | 'xss' | 'command' | 'path' | 'xxe' | 'ssrf' | 'all')[]) => {
        try {
          // Get injection threats (SQL, NoSQL, Command, Path, XXE, SSRF)
          const injectionThreats = this.rasp.detectInjections(input);
          
          // Get XSS threats separately - only for string inputs
          const xssThreats = typeof input === 'string' ? this.rasp.getXSSDetector().detect(input) : [];
          
          const allThreats = [...injectionThreats, ...xssThreats];
          
          if (checks.includes('all')) {
            threats.push(...allThreats);
          } else {
            const typeMap: Record<string, string> = {
              'sql': 'sql_injection',
              'nosql': 'nosql_injection',
              'xss': 'xss',
              'command': 'command_injection',
              'path': 'path_traversal',
              'xxe': 'xxe',
              'ssrf': 'ssrf'
            };
            
            checks.forEach(check => {
              const filtered = allThreats.filter((t: any) => t.type === typeMap[check]);
              threats.push(...filtered);
            });
          }
        } catch (error) {
          this.logger.error('Validation error:', error);
          // On error, assume safe to not break the app
        }

        return {
          sanitize: () => {
            try {
              sanitized = typeof input === 'string' ? this.rasp.sanitizeOutput(input) : input;
            } catch (error) {
              this.logger.error('Sanitization error:', error);
              sanitized = input; // Return original if sanitization fails
            }
            return {
              result: () => ({ safe: threats.length === 0, sanitized, threats })
            };
          },
          result: () => ({ safe: threats.length === 0, input, threats })
        };
      }
    };
  }
}
// Export everything for direct access
export * from './types';
export * from './rasp';
export * from './fuzzing';
export * from './middleware/express';
export { Logger } from './logger';

// Default export
export default Aimless;
