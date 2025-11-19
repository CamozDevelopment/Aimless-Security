import { ThreatType, SecurityThreat } from '../types';

interface RequestProfile {
  ip: string;
  method: string;
  path: string;
  timestamp: number;
  userAgent?: string;
  bodySize?: number;
  statusCode?: number;
  responseTime?: number;
}

interface IPReputation {
  score: number; // 0-100, lower is more suspicious
  lastUpdate: number;
  violations: number;
  blocked: boolean;
}

interface Fingerprint {
  hash: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
}

export class AnomalyDetector {
  private requestHistory: Map<string, RequestProfile[]>;
  private rateLimitMap: Map<string, number[]>;
  private ipReputation: Map<string, IPReputation>;
  private fingerprints: Map<string, Fingerprint>;
  
  private readonly maxHistorySize = 1000;
  private readonly timeWindow = 60000; // 1 minute
  private readonly maxRequestsPerMinute = 100;
  private readonly reputationDecayRate = 0.1; // Reputation improves over time
  
  private readonly suspiciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python-requests/i,
    /go-http-client/i,
    /java/i,
    /perl/i,
    /ruby/i,
    /scan/i,
    /nikto/i,
    /sqlmap/i,
    /nmap/i,
    /masscan/i,
    /metasploit/i,
    /burp/i,
    /zap/i,
    /acunetix/i,
    /nessus/i
  ];

  constructor() {
    this.requestHistory = new Map();
    this.rateLimitMap = new Map();
    this.ipReputation = new Map();
    this.fingerprints = new Map();
  }

  /**
   * Enhanced anomaly detection with behavioral analysis
   */
  detect(
    ip: string,
    method: string,
    path: string,
    userAgent?: string,
    bodySize?: number,
    statusCode?: number,
    responseTime?: number
  ): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    const now = Date.now();

    // Update IP reputation
    this.updateReputation(ip);

    // Check if IP is blocked
    const reputation = this.ipReputation.get(ip);
    if (reputation && reputation.blocked) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Request from blocked IP address',
        timestamp: new Date(),
        blocked: true,
        metadata: { ip, reputationScore: reputation.score, violations: reputation.violations }
      });
      return threats;
    }

    // Create request profile
    const profile: RequestProfile = {
      ip,
      method,
      path,
      timestamp: now,
      userAgent,
      bodySize,
      statusCode,
      responseTime
    };

    // Generate fingerprint
    const fingerprint = this.generateFingerprint(ip, userAgent);
    this.trackFingerprint(fingerprint);

    // Check rate limiting
    const rateThreat = this.checkRateLimit(ip, now);
    if (rateThreat) {
      threats.push(rateThreat);
      this.penalizeReputation(ip, 10);
    }

    // Check for suspicious user agents
    if (userAgent && this.suspiciousPatterns.some(p => p.test(userAgent))) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'medium',
        description: 'Suspicious user agent detected',
        payload: userAgent,
        timestamp: new Date(),
        blocked: false,
        metadata: { ip, userAgent, fingerprint }
      });
      this.penalizeReputation(ip, 5);
    }

    // Check for unusual request patterns
    const patternThreats = this.checkRequestPatterns(ip, profile);
    threats.push(...patternThreats);
    
    if (patternThreats.length > 0) {
      this.penalizeReputation(ip, patternThreats.length * 5);
    }

    // Check for velocity-based anomalies
    const velocityThreats = this.checkVelocity(ip, now);
    threats.push(...velocityThreats);
    
    if (velocityThreats.length > 0) {
      this.penalizeReputation(ip, velocityThreats.length * 3);
    }

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

  /**
   * Update IP reputation (decay over time)
   */
  private updateReputation(ip: string): void {
    let reputation = this.ipReputation.get(ip);
    
    if (!reputation) {
      reputation = {
        score: 100,
        lastUpdate: Date.now(),
        violations: 0,
        blocked: false
      };
      this.ipReputation.set(ip, reputation);
      return;
    }

    // Reputation improves over time
    const timeSinceUpdate = Date.now() - reputation.lastUpdate;
    const improvement = (timeSinceUpdate / 3600000) * this.reputationDecayRate;
    reputation.score = Math.min(100, reputation.score + improvement);
    reputation.lastUpdate = Date.now();
    
    // Unblock if score improves enough
    if (reputation.blocked && reputation.score > 50) {
      reputation.blocked = false;
    }
  }

  /**
   * Penalize IP reputation
   */
  private penalizeReputation(ip: string, penalty: number): void {
    let reputation = this.ipReputation.get(ip);
    
    if (!reputation) {
      reputation = {
        score: 100 - penalty,
        lastUpdate: Date.now(),
        violations: 1,
        blocked: false
      };
    } else {
      reputation.score = Math.max(0, reputation.score - penalty);
      reputation.violations++;
      reputation.lastUpdate = Date.now();
      
      // Block if score drops too low
      if (reputation.score < 20) {
        reputation.blocked = true;
      }
    }
    
    this.ipReputation.set(ip, reputation);
  }

  /**
   * Generate fingerprint from IP and user agent
   */
  private generateFingerprint(ip: string, userAgent?: string): string {
    const crypto = require('crypto');
    const data = `${ip}:${userAgent || 'unknown'}`;
    return crypto.createHash('md5').update(data).digest('hex');
  }

  /**
   * Track fingerprint frequency
   */
  private trackFingerprint(hash: string): void {
    const existing = this.fingerprints.get(hash);
    const now = Date.now();
    
    if (existing) {
      existing.count++;
      existing.lastSeen = now;
    } else {
      this.fingerprints.set(hash, {
        hash,
        count: 1,
        firstSeen: now,
        lastSeen: now
      });
    }
  }

  /**
   * Check request velocity (rapid changes)
   */
  private checkVelocity(ip: string, now: number): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    const history = this.requestHistory.get(ip) || [];
    
    if (history.length < 3) return threats;

    const recentRequests = history.filter(r => now - r.timestamp < 10000); // Last 10 seconds
    
    // Check for burst activity
    if (recentRequests.length > 20) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'high',
        description: 'Burst activity detected',
        timestamp: new Date(),
        blocked: true,
        metadata: { ip, requestCount: recentRequests.length, timeWindow: '10s' }
      });
    }

    // Check for distributed attack pattern
    const uniquePaths = new Set(recentRequests.map(r => r.path));
    if (uniquePaths.size > 15 && recentRequests.length > 15) {
      threats.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Potential distributed attack or scanning detected',
        timestamp: new Date(),
        blocked: true,
        metadata: { ip, uniquePaths: uniquePaths.size, requests: recentRequests.length }
      });
    }

    return threats;
  }

  clearHistory(ip?: string): void {
    if (ip) {
      this.requestHistory.delete(ip);
      this.rateLimitMap.delete(ip);
      this.ipReputation.delete(ip);
    } else {
      this.requestHistory.clear();
      this.rateLimitMap.clear();
      this.ipReputation.clear();
      this.fingerprints.clear();
    }
  }

  /**
   * Get IP reputation score
   */
  getReputationScore(ip: string): number {
    const reputation = this.ipReputation.get(ip);
    return reputation ? reputation.score : 100;
  }

  /**
   * Block or unblock an IP
   */
  setIPBlocked(ip: string, blocked: boolean): void {
    let reputation = this.ipReputation.get(ip);
    
    if (!reputation) {
      reputation = {
        score: blocked ? 0 : 100,
        lastUpdate: Date.now(),
        violations: blocked ? 1 : 0,
        blocked
      };
    } else {
      reputation.blocked = blocked;
      if (blocked) {
        reputation.score = 0;
      }
    }
    
    this.ipReputation.set(ip, reputation);
  }

  /**
   * Get statistics for monitoring
   */
  getStats(): {
    totalIPs: number;
    blockedIPs: number;
    totalRequests: number;
    uniqueFingerprints: number;
  } {
    let totalRequests = 0;
    let blockedIPs = 0;

    for (const [, requests] of this.requestHistory) {
      totalRequests += requests.length;
    }

    for (const [, reputation] of this.ipReputation) {
      if (reputation.blocked) blockedIPs++;
    }

    return {
      totalIPs: this.requestHistory.size,
      blockedIPs,
      totalRequests,
      uniqueFingerprints: this.fingerprints.size
    };
  }
}
