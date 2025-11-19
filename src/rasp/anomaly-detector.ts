import { ThreatType, SecurityThreat } from '../types';

interface RequestProfile {
  ip: string;
  method: string;
  path: string;
  timestamp: number;
  userAgent?: string;
  bodySize?: number;
}

export class AnomalyDetector {
  private requestHistory: Map<string, RequestProfile[]>;
  private rateLimitMap: Map<string, number[]>;
  private readonly maxHistorySize = 1000;
  private readonly timeWindow = 60000; // 1 minute
  private readonly maxRequestsPerMinute = 100;
  private readonly suspiciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /go-http/i
  ];

  constructor() {
    this.requestHistory = new Map();
    this.rateLimitMap = new Map();
  }

  detect(
    ip: string,
    method: string,
    path: string,
    userAgent?: string,
    bodySize?: number
  ): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    const now = Date.now();

    // Create request profile
    const profile: RequestProfile = {
      ip,
      method,
      path,
      timestamp: now,
      userAgent,
      bodySize
    };

    // Check rate limiting
    const rateThreat = this.checkRateLimit(ip, now);
    if (rateThreat) threats.push(rateThreat);

    // Check for suspicious user agents
    if (userAgent && this.suspiciousPatterns.some(p => p.test(userAgent))) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'medium',
        description: 'Suspicious user agent detected',
        payload: userAgent,
        timestamp: new Date(),
        blocked: false,
        metadata: { ip, userAgent }
      });
    }

    // Check for unusual request patterns
    const patternThreats = this.checkRequestPatterns(ip, profile);
    threats.push(...patternThreats);

    // Store request history
    this.storeRequest(ip, profile);

    return threats;
  }

  private checkRateLimit(ip: string, now: number): SecurityThreat | null {
    let timestamps = this.rateLimitMap.get(ip) || [];
    
    // Remove old timestamps
    timestamps = timestamps.filter(t => now - t < this.timeWindow);
    
    // Add current timestamp
    timestamps.push(now);
    this.rateLimitMap.set(ip, timestamps);

    // Check if rate limit exceeded
    if (timestamps.length > this.maxRequestsPerMinute) {
      return {
        type: ThreatType.RATE_LIMIT_EXCEEDED,
        severity: 'medium',
        description: `Rate limit exceeded: ${timestamps.length} requests in ${this.timeWindow}ms`,
        timestamp: new Date(),
        blocked: true,
        metadata: { ip, requestCount: timestamps.length }
      };
    }

    return null;
  }

  private checkRequestPatterns(ip: string, current: RequestProfile): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    const history = this.requestHistory.get(ip) || [];

    if (history.length < 5) return threats;

    const recentRequests = history.slice(-10);
    
    // Check for rapid sequential requests to different endpoints
    const uniquePaths = new Set(recentRequests.map(r => r.path));
    if (uniquePaths.size > 8 && recentRequests.length === 10) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'medium',
        description: 'Potential scanning activity detected',
        timestamp: new Date(),
        blocked: false,
        metadata: { ip, uniqueEndpoints: uniquePaths.size }
      });
    }

    // Check for repeated failed attempts (based on error patterns in path)
    const errorPaths = recentRequests.filter(r => 
      r.path.includes('login') || 
      r.path.includes('auth') ||
      r.path.includes('admin')
    );
    
    if (errorPaths.length > 5) {
      threats.push({
        type: ThreatType.AUTH_BYPASS_ATTEMPT,
        severity: 'high',
        description: 'Potential authentication bypass attempt detected',
        timestamp: new Date(),
        blocked: true,
        metadata: { ip, attempts: errorPaths.length }
      });
    }

    // Check for unusually large request bodies
    if (current.bodySize && current.bodySize > 10 * 1024 * 1024) { // 10MB
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'medium',
        description: 'Unusually large request body detected',
        timestamp: new Date(),
        blocked: false,
        metadata: { ip, bodySize: current.bodySize }
      });
    }

    return threats;
  }

  private storeRequest(ip: string, profile: RequestProfile): void {
    let history = this.requestHistory.get(ip) || [];
    history.push(profile);

    // Limit history size
    if (history.length > this.maxHistorySize) {
      history = history.slice(-this.maxHistorySize);
    }

    this.requestHistory.set(ip, history);
  }

  clearHistory(ip?: string): void {
    if (ip) {
      this.requestHistory.delete(ip);
      this.rateLimitMap.delete(ip);
    } else {
      this.requestHistory.clear();
      this.rateLimitMap.clear();
    }
  }
}
