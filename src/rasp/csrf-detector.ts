import { ThreatType, SecurityThreat } from '../types';
import * as crypto from 'crypto';

interface TokenData {
  token: string;
  expires: number;
  createdAt: number;
  used: boolean;
}

export class CSRFDetector {
  private trustedOrigins: Set<string>;
  private tokenStore: Map<string, TokenData>;
  private readonly defaultExpiry = 3600000; // 1 hour
  private readonly cleanupInterval = 300000; // 5 minutes
  private cleanupTimer?: ReturnType<typeof setInterval>;

  constructor(trustedOrigins: string[] = []) {
    this.trustedOrigins = new Set(trustedOrigins);
    this.tokenStore = new Map();
    this.startCleanup();
  }

  /**
   * Auto-cleanup expired tokens
   */
  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredTokens();
    }, this.cleanupInterval);
  }

  /**
   * Clean up expired tokens to prevent memory leaks
   */
  private cleanupExpiredTokens(): void {
    const now = Date.now();
    for (const [sessionId, data] of this.tokenStore.entries()) {
      if (data.expires < now) {
        this.tokenStore.delete(sessionId);
      }
    }
  }

  /**
   * Stop cleanup timer (call when shutting down)
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
  }

  /**
   * Generate a cryptographically secure CSRF token
   */
  generateToken(sessionId: string, expiryMs?: number): string {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + (expiryMs || this.defaultExpiry);
    const createdAt = Date.now();
    
    this.tokenStore.set(sessionId, { token, expires, createdAt, used: false });
    
    return token;
  }

  /**
   * Validate CSRF token with one-time use option
   */
  validateToken(sessionId: string, token: string, oneTimeUse: boolean = false): boolean {
    const stored = this.tokenStore.get(sessionId);
    
    if (!stored) return false;
    
    // Check expiry
    if (stored.expires < Date.now()) {
      this.tokenStore.delete(sessionId);
      return false;
    }
    
    // Check if already used (for one-time tokens)
    if (oneTimeUse && stored.used) {
      return false;
    }
    
    // Validate token using timing-safe comparison
    const isValid = this.timingSafeEqual(stored.token, token);
    
    if (isValid && oneTimeUse) {
      stored.used = true;
    }
    
    return isValid;
  }

  /**
   * Timing-safe comparison to prevent timing attacks
   */
  private timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Enhanced CSRF detection with better origin validation
   */
  detect(
    method: string,
    origin: string | undefined,
    referer: string | undefined,
    csrfToken: string | undefined,
    sessionId: string | undefined,
    cookies?: Record<string, string>
  ): SecurityThreat | null {
    // Only check state-changing methods
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
      return null;
    }

    // Check Origin header
    if (origin) {
      try {
        const originUrl = new URL(origin);
        if (!this.isTrustedOrigin(originUrl.origin)) {
          return {
            type: ThreatType.CSRF,
            severity: 'critical',
            description: 'CSRF attack detected: Untrusted origin',
            payload: origin,
            timestamp: new Date(),
            blocked: true,
            metadata: { method, origin, check: 'origin-header' }
          };
        }
      } catch (e) {
        // Invalid origin URL
        return {
          type: ThreatType.CSRF,
          severity: 'high',
          description: 'CSRF attack detected: Invalid origin header',
          payload: origin,
          timestamp: new Date(),
          blocked: true,
          metadata: { method, origin, check: 'origin-invalid' }
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
            metadata: { method, referer, check: 'referer-header' }
          };
        }
      } catch (e) {
        // Invalid referer - might be stripped, don't block
      }
    }

    // Double-submit cookie check
    if (cookies && cookies['csrf-token']) {
      if (csrfToken !== cookies['csrf-token']) {
        return {
          type: ThreatType.CSRF,
          severity: 'high',
          description: 'CSRF attack detected: Cookie mismatch',
          timestamp: new Date(),
          blocked: true,
          metadata: { method, check: 'double-submit-cookie' }
        };
      }
    }

    // Check CSRF token (synchronizer token pattern)
    if (sessionId && !this.validateToken(sessionId, csrfToken || '')) {
      return {
        type: ThreatType.CSRF,
        severity: 'high',
        description: 'CSRF attack detected: Invalid or missing token',
        timestamp: new Date(),
        blocked: true,
        metadata: { method, hasToken: !!csrfToken, check: 'synchronizer-token' }
      };
    }

    return null;
  }

  /**
   * Check if origin is trusted
   */
  private isTrustedOrigin(origin: string): boolean {
    if (this.trustedOrigins.size === 0) return true;
    return this.trustedOrigins.has(origin);
  }

  /**
   * Add a trusted origin
   */
  addTrustedOrigin(origin: string): void {
    this.trustedOrigins.add(origin);
  }

  /**
   * Remove a trusted origin
   */
  removeTrustedOrigin(origin: string): void {
    this.trustedOrigins.delete(origin);
  }

  /**
   * Get all trusted origins
   */
  getTrustedOrigins(): string[] {
    return Array.from(this.trustedOrigins);
  }

  /**
   * Revoke a specific token
   */
  revokeToken(sessionId: string): boolean {
    return this.tokenStore.delete(sessionId);
  }

  /**
   * Get token info (for debugging/monitoring)
   */
  getTokenInfo(sessionId: string): { valid: boolean; expiresIn?: number; used?: boolean } {
    const stored = this.tokenStore.get(sessionId);
    
    if (!stored) {
      return { valid: false };
    }
    
    const now = Date.now();
    const valid = stored.expires > now;
    
    return {
      valid,
      expiresIn: valid ? stored.expires - now : 0,
      used: stored.used
    };
  }
}
