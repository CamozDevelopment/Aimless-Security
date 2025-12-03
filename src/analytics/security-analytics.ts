import { SecurityThreat, SecurityAnalytics } from '../types';

interface AnalyticsEntry {
  timestamp: Date;
  ip: string;
  path: string;
  method: string;
  threats: SecurityThreat[];
  blocked: boolean;
  responseTime?: number;
}

export class SecurityAnalyticsEngine {
  private entries: AnalyticsEntry[] = [];
  private retentionDays: number;
  private startTime: Date;
  private requestCount: number = 0;

  constructor(retentionDays: number = 30) {
    this.retentionDays = retentionDays;
    this.startTime = new Date();
    
    // Cleanup old entries every hour
    setInterval(() => this.cleanup(), 3600000);
  }

  logRequest(entry: Omit<AnalyticsEntry, 'timestamp'>): void {
    this.requestCount++;
    this.entries.push({
      ...entry,
      timestamp: new Date()
    });

    // Keep entries within retention period
    if (this.entries.length > 100000) { // Memory safety
      this.cleanup();
    }
  }

  private cleanup(): void {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);
    
    this.entries = this.entries.filter(e => e.timestamp >= cutoffDate);
  }

  getAnalytics(): SecurityAnalytics {
    const totalRequests = this.requestCount;
    const threatsDetected = this.entries.filter(e => e.threats.length > 0).length;
    const threatsBlocked = this.entries.filter(e => e.blocked).length;

    // Top attack types
    const attackTypeCounts = new Map<string, number>();
    this.entries.forEach(entry => {
      entry.threats.forEach(threat => {
        attackTypeCounts.set(
          threat.type,
          (attackTypeCounts.get(threat.type) || 0) + 1
        );
      });
    });

    const topAttackTypes = Array.from(attackTypeCounts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Top attacking IPs
    const ipCounts = new Map<string, { count: number; reputation: number }>();
    this.entries.forEach(entry => {
      if (entry.threats.length > 0) {
        const existing = ipCounts.get(entry.ip) || { count: 0, reputation: 100 };
        ipCounts.set(entry.ip, {
          count: existing.count + entry.threats.length,
          reputation: Math.max(0, existing.reputation - entry.threats.length * 5)
        });
      }
    });

    const topAttackIPs = Array.from(ipCounts.entries())
      .map(([ip, data]) => ({ ip, count: data.count, reputation: data.reputation }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Requests by hour (last 24 hours)
    const requestsByHour = this.getRequestsByHour();

    // Average response time
    const responseTimes = this.entries
      .filter(e => e.responseTime !== undefined)
      .map(e => e.responseTime!);
    const averageResponseTime = responseTimes.length > 0
      ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
      : 0;

    // Uptime
    const uptime = Date.now() - this.startTime.getTime();

    return {
      totalRequests,
      threatsDetected,
      threatsBlocked,
      topAttackTypes,
      topAttackIPs,
      requestsByHour,
      averageResponseTime,
      uptime
    };
  }

  private getRequestsByHour(): Array<{ hour: number; count: number; threats: number }> {
    const now = new Date();
    const hourlyData = new Map<number, { count: number; threats: number }>();

    // Initialize last 24 hours
    for (let i = 0; i < 24; i++) {
      const hour = (now.getHours() - i + 24) % 24;
      hourlyData.set(hour, { count: 0, threats: 0 });
    }

    // Count requests in last 24 hours
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    this.entries
      .filter(e => e.timestamp >= oneDayAgo)
      .forEach(entry => {
        const hour = entry.timestamp.getHours();
        const data = hourlyData.get(hour)!;
        data.count++;
        if (entry.threats.length > 0) {
          data.threats += entry.threats.length;
        }
      });

    return Array.from(hourlyData.entries())
      .map(([hour, data]) => ({ hour, ...data }))
      .sort((a, b) => a.hour - b.hour);
  }

  exportData(): AnalyticsEntry[] {
    return [...this.entries];
  }

  getMetricsSummary(): string {
    const analytics = this.getAnalytics();
    const threatRate = analytics.totalRequests > 0 
      ? ((analytics.threatsDetected / analytics.totalRequests) * 100).toFixed(2)
      : '0.00';
    const blockRate = analytics.threatsDetected > 0
      ? ((analytics.threatsBlocked / analytics.threatsDetected) * 100).toFixed(2)
      : '0.00';

    return `
📊 Security Analytics Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Requests: ${analytics.totalRequests.toLocaleString()}
Threats Detected: ${analytics.threatsDetected.toLocaleString()} (${threatRate}%)
Threats Blocked: ${analytics.threatsBlocked.toLocaleString()} (${blockRate}% block rate)
Avg Response Time: ${analytics.averageResponseTime.toFixed(2)}ms
Uptime: ${this.formatUptime(analytics.uptime)}

Top Attack Types:
${analytics.topAttackTypes.slice(0, 5).map((t, i) => 
  `${i + 1}. ${t.type}: ${t.count} attacks`).join('\n')}

Top Attacking IPs:
${analytics.topAttackIPs.slice(0, 5).map((ip, i) => 
  `${i + 1}. ${ip.ip}: ${ip.count} attacks (reputation: ${ip.reputation})`).join('\n')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `.trim();
  }

  private formatUptime(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }
}
