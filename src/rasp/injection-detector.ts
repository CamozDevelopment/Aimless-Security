import { ThreatType, SecurityThreat } from '../types';

export class InjectionDetector {
  // SQL Injection patterns
  private sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/i,
    /(\bOR\b\s+\d+\s*=\s*\d+)/i,
    /(\bAND\b\s+\d+\s*=\s*\d+)/i,
    /(;|--|\/\*|\*\/|xp_|sp_)/i,
    /(\bUNION\b.*\bSELECT\b)/i,
    /('|")\s*(OR|AND)\s*('|")\s*=\s*('|")/i,
    /(0x[0-9a-f]+)/i,
    /(\bCHAR\b\s*\()/i,
    /(\bCONCAT\b\s*\()/i
  ];

  // NoSQL Injection patterns
  private nosqlPatterns = [
    /\$where/i,
    /\$ne/i,
    /\$gt/i,
    /\$lt/i,
    /\$regex/i,
    /\$in/i,
    /\$nin/i,
    /\$exists/i,
    /\{\s*['"]\$[a-z]+['"]\s*:/i
  ];

  // Command Injection patterns
  private commandPatterns = [
    /[;&|`$(){}[\]<>]/,
    /\b(cat|ls|dir|ping|whoami|wget|curl|nc|netcat|bash|sh|cmd|powershell)\b/i,
    /\.\.\//,
    /~\//,
    /(\r\n|\n|\r)/
  ];

  // Path Traversal patterns
  private pathTraversalPatterns = [
    /\.\.[\/\\]/,
    /%2e%2e[\/\\]/i,
    /\.\.[%]{2}[f5][\/\\]/i,
    /(\/|\\)(etc|windows|system32|boot|proc)/i,
    /\0/
  ];

  // XXE patterns
  private xxePatterns = [
    /<!ENTITY/i,
    /<!DOCTYPE/i,
    /SYSTEM\s+["']/i,
    /PUBLIC\s+["']/i
  ];

  // SSRF patterns
  private ssrfPatterns = [
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /169\.254\./,
    /192\.168\./,
    /10\./,
    /172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /::1/,
    /0x7f/i,
    /@/
  ];

  detect(input: any, context: string = 'unknown'): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    
    if (!input) return threats;

    const inputs = this.extractInputs(input);

    for (const value of inputs) {
      if (typeof value !== 'string') continue;

      // SQL Injection detection
      if (this.sqlPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.SQL_INJECTION,
          severity: 'high',
          description: 'Potential SQL injection detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }

      // NoSQL Injection detection
      if (this.nosqlPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.NOSQL_INJECTION,
          severity: 'high',
          description: 'Potential NoSQL injection detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }

      // Command Injection detection
      if (this.commandPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.COMMAND_INJECTION,
          severity: 'critical',
          description: 'Potential command injection detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }

      // Path Traversal detection
      if (this.pathTraversalPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.PATH_TRAVERSAL,
          severity: 'high',
          description: 'Potential path traversal detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }

      // XXE detection
      if (this.xxePatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.XXE,
          severity: 'high',
          description: 'Potential XXE attack detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }

      // SSRF detection
      if (this.ssrfPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.SSRF,
          severity: 'medium',
          description: 'Potential SSRF attack detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context }
        });
      }
    }

    return threats;
  }

  private extractInputs(input: any): string[] {
    const inputs: string[] = [];

    if (typeof input === 'string') {
      inputs.push(input);
    } else if (Array.isArray(input)) {
      for (const item of input) {
        inputs.push(...this.extractInputs(item));
      }
    } else if (typeof input === 'object' && input !== null) {
      for (const key in input) {
        inputs.push(key);
        inputs.push(...this.extractInputs(input[key]));
      }
    }

    return inputs;
  }
}
