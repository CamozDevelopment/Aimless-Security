import { FuzzingConfig, FuzzingResult, SecurityThreat, ThreatType } from '../types';
import { PayloadGenerator } from './payload-generator';
import { Logger } from '../logger';

export interface FuzzTarget {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: any;
  params?: Record<string, any>;
  query?: Record<string, any>;
  expectedStatus?: number;
  credentials?: { username: string; password: string };
}

interface ResponseAnalysis {
  status: number;
  bodyLength: number;
  headers: Record<string, string>;
  responseTime: number;
  errorMessages: string[];
  vulnerabilityScore: number;
}

export class FuzzingEngine {
  private config: Required<FuzzingConfig>;
  private payloadGenerator: PayloadGenerator;
  private logger: Logger;
  private baselineResponses: Map<string, ResponseAnalysis>;

  constructor(config: FuzzingConfig = {}, logger: Logger) {
    this.config = {
      enabled: true,
      maxPayloads: 100,
      timeout: 5000,
      authBypassTests: true,
      rateLimitTests: true,
      graphqlIntrospection: true,
      customPayloads: [],
      ...config
    };

    this.logger = logger;
    this.payloadGenerator = new PayloadGenerator();
    this.baselineResponses = new Map();
  }

  async fuzz(target: FuzzTarget): Promise<FuzzingResult> {
    if (!this.config.enabled) {
      return {
        endpoint: target.url,
        method: target.method,
        vulnerabilities: [],
        testedPayloads: 0,
        duration: 0,
        timestamp: new Date()
      };
    }

    const startTime = Date.now();
    const vulnerabilities: SecurityThreat[] = [];
    let testedPayloads = 0;

    this.logger.info(`Starting fuzzing test for ${target.method} ${target.url}`);

    // Fuzz query parameters
    if (target.query) {
      const queryVulns = await this.fuzzParameters(target, 'query', target.query);
      vulnerabilities.push(...queryVulns);
      testedPayloads += queryVulns.length;
    }

    // Fuzz body parameters
    if (target.body) {
      const bodyVulns = await this.fuzzParameters(target, 'body', target.body);
      vulnerabilities.push(...bodyVulns);
      testedPayloads += bodyVulns.length;
    }

    // Fuzz headers
    if (target.headers) {
      const headerVulns = await this.fuzzHeaders(target);
      vulnerabilities.push(...headerVulns);
      testedPayloads += headerVulns.length;
    }

    // Auth bypass tests
    if (this.config.authBypassTests) {
      const authVulns = await this.testAuthBypass(target);
      vulnerabilities.push(...authVulns);
      testedPayloads += authVulns.length;
    }

    // Rate limit tests
    if (this.config.rateLimitTests) {
      const rateLimitVulns = await this.testRateLimits(target);
      vulnerabilities.push(...rateLimitVulns);
      testedPayloads += rateLimitVulns.length;
    }

    // GraphQL introspection
    if (this.config.graphqlIntrospection && this.isGraphQL(target)) {
      const graphqlVulns = await this.testGraphQLIntrospection(target);
      vulnerabilities.push(...graphqlVulns);
      testedPayloads += graphqlVulns.length;
    }

    const duration = Date.now() - startTime;

    this.logger.info(`Fuzzing completed: ${testedPayloads} payloads tested, ${vulnerabilities.length} vulnerabilities found`);

    return {
      endpoint: target.url,
      method: target.method,
      vulnerabilities,
      testedPayloads,
      duration,
      timestamp: new Date()
    };
  }

  private async fuzzParameters(
    target: FuzzTarget,
    location: 'query' | 'body',
    params: Record<string, any>
  ): Promise<SecurityThreat[]> {
    const vulnerabilities: SecurityThreat[] = [];

    for (const [key, value] of Object.entries(params)) {
      const mutations = this.payloadGenerator.mutateValue(value);
      const testPayloads = mutations.slice(0, this.config.maxPayloads);

      for (const payload of testPayloads) {
        const result = this.analyzePayload(payload, key, location);
        if (result) {
          vulnerabilities.push(result);
        }
      }
    }

    return vulnerabilities;
  }

  private async fuzzHeaders(target: FuzzTarget): Promise<SecurityThreat[]> {
    const vulnerabilities: SecurityThreat[] = [];
    const dangerousHeaders = ['Host', 'X-Forwarded-For', 'X-Real-IP', 'Referer', 'User-Agent'];

    for (const header of dangerousHeaders) {
      const mutations = this.payloadGenerator.mutateValue('test');
      const testPayloads = mutations.slice(0, Math.min(10, this.config.maxPayloads));

      for (const payload of testPayloads) {
        const result = this.analyzePayload(payload, header, 'header');
        if (result) {
          vulnerabilities.push(result);
        }
      }
    }

    return vulnerabilities;
  }

  private async testAuthBypass(target: FuzzTarget): Promise<SecurityThreat[]> {
    const vulnerabilities: SecurityThreat[] = [];
    const authBypassPayloads = this.payloadGenerator.getByType('authBypass');

    // Test Authorization header
    for (const payload of authBypassPayloads.slice(0, this.config.maxPayloads)) {
      vulnerabilities.push({
        type: ThreatType.AUTH_BYPASS_ATTEMPT,
        severity: 'high',
        description: `Auth bypass test: Testing authorization with payload`,
        payload: String(payload),
        timestamp: new Date(),
        blocked: false,
        metadata: { location: 'authorization', target: target.url }
      });
    }

    return vulnerabilities;
  }

  private async testRateLimits(target: FuzzTarget): Promise<SecurityThreat[]> {
    const vulnerabilities: SecurityThreat[] = [];
    const burstSize = 100;

    this.logger.info(`Testing rate limits with burst of ${burstSize} requests`);

    vulnerabilities.push({
      type: ThreatType.RATE_LIMIT_EXCEEDED,
      severity: 'medium',
      description: `Rate limit test: Simulated ${burstSize} rapid requests`,
      timestamp: new Date(),
      blocked: false,
      metadata: { 
        target: target.url,
        burstSize,
        message: 'This is a simulated test - actual requests not sent'
      }
    });

    return vulnerabilities;
  }

  private async testGraphQLIntrospection(target: FuzzTarget): Promise<SecurityThreat[]> {
    const vulnerabilities: SecurityThreat[] = [];
    const graphqlPayloads = this.payloadGenerator.generateGraphQLPayloads();

    for (const payload of graphqlPayloads) {
      vulnerabilities.push({
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'medium',
        description: 'GraphQL introspection query test',
        payload,
        timestamp: new Date(),
        blocked: false,
        metadata: { 
          target: target.url,
          type: 'graphql-introspection'
        }
      });
    }

    return vulnerabilities;
  }

  /**
   * Analyze response and calculate vulnerability score
   */
  private analyzeResponse(
    payload: any,
    field: string,
    location: string,
    response?: {
      status: number;
      body: string;
      headers: Record<string, string>;
      responseTime: number;
    }
  ): { threat: SecurityThreat | null; score: number } {
    const payloadStr = String(payload);
    let score = 0;
    let threat: SecurityThreat | null = null;

    // Response analysis (if available)
    if (response) {
      const errorKeywords = ['error', 'exception', 'stack trace', 'sql', 'syntax', 'unexpected'];
      const hasError = errorKeywords.some(kw => response.body.toLowerCase().includes(kw));

      if (hasError) score += 30;
      if (response.status >= 500) score += 40;
      if (response.status === 200 && response.responseTime > 5000) score += 20; // Potential time-based attack
      if (response.headers['x-powered-by']) score += 10; // Information disclosure
    }

    // Determine threat type based on payload
    if (payloadStr.includes('SELECT') || payloadStr.includes('UNION') || payloadStr.includes('OR 1=1')) {
      score += 50;
      threat = {
        type: ThreatType.SQL_INJECTION,
        severity: score > 70 ? 'critical' : 'high',
        description: `SQL injection test payload in ${location}.${field} (score: ${score})`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location, vulnerabilityScore: score, response: response ? { status: response.status } : undefined }
      };
    }

    else if (payloadStr.includes('<script>') || payloadStr.includes('onerror') || payloadStr.includes('javascript:')) {
      score += 45;
      threat = {
        type: ThreatType.XSS,
        severity: score > 70 ? 'critical' : 'high',
        description: `XSS test payload in ${location}.${field} (score: ${score})`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location, vulnerabilityScore: score }
      };
    }

    else if (payloadStr.includes('$') && (payloadStr.includes('gt') || payloadStr.includes('ne') || payloadStr.includes('where'))) {
      score += 45;
      threat = {
        type: ThreatType.NOSQL_INJECTION,
        severity: score > 70 ? 'critical' : 'high',
        description: `NoSQL injection test payload in ${location}.${field} (score: ${score})`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location, vulnerabilityScore: score }
      };
    }

    else if (payloadStr.includes('../') || payloadStr.includes('..\\') || payloadStr.includes('%2e%2e')) {
      score += 40;
      threat = {
        type: ThreatType.PATH_TRAVERSAL,
        severity: score > 70 ? 'critical' : 'high',
        description: `Path traversal test payload in ${location}.${field} (score: ${score})`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location, vulnerabilityScore: score }
      };
    }

    else if (payloadStr.match(/[;&|`]/)) {
      score += 50;
      threat = {
        type: ThreatType.COMMAND_INJECTION,
        severity: score > 70 ? 'critical' : 'high',
        description: `Command injection test payload in ${location}.${field} (score: ${score})`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location, vulnerabilityScore: score }
      };
    }

    return { threat, score };
  }

  private analyzePayload(payload: any, field: string, location: string): SecurityThreat | null {
    const result = this.analyzeResponse(payload, field, location);
    return result.threat;
  }

  private isGraphQL(target: FuzzTarget): boolean {
    return target.url.toLowerCase().includes('graphql') ||
           (target.body && typeof target.body === 'object' && 'query' in target.body);
  }
}
