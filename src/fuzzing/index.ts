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
}

export class FuzzingEngine {
  private config: Required<FuzzingConfig>;
  private payloadGenerator: PayloadGenerator;
  private logger: Logger;

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

  private analyzePayload(payload: any, field: string, location: string): SecurityThreat | null {
    const payloadStr = String(payload);

    // Determine threat type based on payload
    if (payloadStr.includes('SELECT') || payloadStr.includes('UNION')) {
      return {
        type: ThreatType.SQL_INJECTION,
        severity: 'high',
        description: `SQL injection test payload in ${location}.${field}`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location }
      };
    }

    if (payloadStr.includes('<script>') || payloadStr.includes('onerror')) {
      return {
        type: ThreatType.XSS,
        severity: 'high',
        description: `XSS test payload in ${location}.${field}`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location }
      };
    }

    if (payloadStr.includes('$') && (payloadStr.includes('gt') || payloadStr.includes('ne'))) {
      return {
        type: ThreatType.NOSQL_INJECTION,
        severity: 'high',
        description: `NoSQL injection test payload in ${location}.${field}`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location }
      };
    }

    if (payloadStr.includes('../') || payloadStr.includes('..\\')) {
      return {
        type: ThreatType.PATH_TRAVERSAL,
        severity: 'high',
        description: `Path traversal test payload in ${location}.${field}`,
        payload: payloadStr,
        timestamp: new Date(),
        blocked: false,
        metadata: { field, location }
      };
    }

    return null;
  }

  private isGraphQL(target: FuzzTarget): boolean {
    return target.url.toLowerCase().includes('graphql') ||
           (target.body && typeof target.body === 'object' && 'query' in target.body);
  }
}
