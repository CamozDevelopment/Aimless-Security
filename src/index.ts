import { AimlessConfig } from './types';
import { RASP } from './rasp';
import { FuzzingEngine, FuzzTarget } from './fuzzing';
import { Logger } from './logger';
import { createMiddleware, csrfProtection } from './middleware/express';

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
}

// Export everything for direct access
export * from './types';
export * from './rasp';
export * from './fuzzing';
export * from './middleware/express';
export { Logger } from './logger';

// Default export
export default Aimless;
