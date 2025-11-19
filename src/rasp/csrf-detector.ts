import { ThreatType, SecurityThreat } from '../types';
import * as crypto from 'crypto';

export class CSRFDetector {
  private trustedOrigins: Set<string>;
  private tokenStore: Map<string, { token: string; expires: number }>;

  constructor(trustedOrigins: string[] = []) {
    this.trustedOrigins = new Set(trustedOrigins);
    this.tokenStore = new Map();
  }

  generateToken(sessionId: string): string {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour
    
    this.tokenStore.set(sessionId, { token, expires });
    
    return token;
  }

  validateToken(sessionId: string, token: string): boolean {
    const stored = this.tokenStore.get(sessionId);
    
    if (!stored) return false;
    if (stored.expires < Date.now()) {
      this.tokenStore.delete(sessionId);
      return false;
    }
    
    return stored.token === token;
  }

  detect(
    method: string,
    origin: string | undefined,
    referer: string | undefined,
    csrfToken: string | undefined,
    sessionId: string | undefined
  ): SecurityThreat | null {
    // Only check state-changing methods
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
      return null;
    }

    // Check Origin header
    if (origin) {
      const originUrl = new URL(origin);
      if (!this.isTrustedOrigin(originUrl.origin)) {
        return {
          type: ThreatType.CSRF,
          severity: 'high',
          description: 'CSRF attack detected: Untrusted origin',
          payload: origin,
          timestamp: new Date(),
          blocked: true,
          metadata: { method, origin }
        };
      }
    }

    // Check Referer header as fallback
    if (!origin && referer) {
      try {
        const refererUrl = new URL(referer);
        if (!this.isTrustedOrigin(refererUrl.origin)) {
          return {
            type: ThreatType.CSRF,
            severity: 'high',
            description: 'CSRF attack detected: Untrusted referer',
            payload: referer,
            timestamp: new Date(),
            blocked: true,
            metadata: { method, referer }
          };
        }
      } catch (e) {
        // Invalid referer URL
      }
    }

    // Check CSRF token
    if (sessionId && !this.validateToken(sessionId, csrfToken || '')) {
      return {
        type: ThreatType.CSRF,
        severity: 'high',
        description: 'CSRF attack detected: Invalid or missing token',
        timestamp: new Date(),
        blocked: true,
        metadata: { method, hasToken: !!csrfToken }
      };
    }

    return null;
  }

  private isTrustedOrigin(origin: string): boolean {
    if (this.trustedOrigins.size === 0) return true;
    return this.trustedOrigins.has(origin);
  }

  addTrustedOrigin(origin: string): void {
    this.trustedOrigins.add(origin);
  }

  removeTrustedOrigin(origin: string): void {
    this.trustedOrigins.delete(origin);
  }
}
