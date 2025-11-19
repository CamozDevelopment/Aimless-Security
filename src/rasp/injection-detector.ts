import { ThreatType, SecurityThreat } from '../types';

export class InjectionDetector {
  // Enhanced SQL Injection patterns with context awareness
  private sqlPatterns = [
    // SQL Keywords - more comprehensive
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE|TRUNCATE|MERGE|REPLACE)\b)/i,
    // Tautology-based injections
    /(\bOR\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/i,
    /(\bAND\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/i,
    /(\bOR\b\s+\d+\s*[=<>]+\s*\d+)/i,
    /(\bAND\b\s+\d+\s*[=<>]+\s*\d+)/i,
    // SQL comments and terminators
    /(--|#|\/\*|\*\/|;)\s*$/,
    /';?\s*(--|#)/,
    // Union-based injections
    /(\bUNION\b\s+(ALL\s+)?SELECT\b)/i,
    // Quote manipulation
    /('|")\s*(OR|AND)\s*('|")\s*=\s*('|")/i,
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /"\s*OR\s*"1"\s*=\s*"1/i,
    // Hex encoding
    /(0x[0-9a-fA-F]{2,})/,
    // SQL functions
    /(\b(CHAR|CONCAT|SUBSTRING|ASCII|ORD|HEX|UNHEX|BENCHMARK|SLEEP|WAITFOR|DELAY)\b\s*\()/i,
    // Stored procedures
    /\b(xp_|sp_)\w+/i,
    // Stacked queries
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)/i,
    // Time-based blind injection
    /\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\b/i,
    // Error-based injection
    /\b(EXTRACTVALUE|UPDATEXML|EXP|POW)\b\s*\(/i,
    // Information schema access
    /\b(information_schema|sys\.|mysql\.|performance_schema)\b/i
  ];

  // Enhanced NoSQL Injection patterns
  private nosqlPatterns = [
    // MongoDB operators
    /\$where/i,
    /\$(ne|eq|gt|gte|lt|lte|in|nin|regex|exists|type|mod|text|all|elemMatch)/i,
    // Object notation
    /\{\s*['"]\$[a-z]+['"]\s*:/i,
    // JavaScript injection in MongoDB
    /\bthis\b\s*\.\s*\w+/,
    /\bfunction\s*\(/,
    /\beval\s*\(/,
    // NoSQL aggregation
    /\$(match|group|project|lookup|unwind)/i,
    // CouchDB/PouchDB
    /_design\//,
    /_view\//,
    // Redis commands
    /\b(FLUSHALL|FLUSHDB|CONFIG|EVAL|SCRIPT)\b/i,
    // Cassandra CQL
    /\b(ALLOW\s+FILTERING|BATCH)\b/i
  ];

  // Enhanced Command Injection patterns
  private commandPatterns = [
    // Command separators and operators
    /[;&|`$(){}[\]<>]/,
    /(\|\||&&)/,
    // Common shell commands
    /\b(cat|ls|dir|pwd|cd|echo|printf|ping|whoami|id|uname|wget|curl|nc|netcat|ncat|bash|sh|zsh|csh|ksh|cmd|powershell|pwsh)\b/i,
    // Path traversal in commands
    /(\.\.[\/\\]|~\/)/,
    // Newline injections
    /(\r\n|\n|\r|%0a|%0d)/,
    // Backticks and command substitution
    /`[^`]*`/,
    /\$\([^)]*\)/,
    // PowerShell specific
    /\b(Invoke-Expression|IEX|Invoke-Command|ICM|Get-Content|GC)\b/i,
    // File redirection
    /[><]{1,2}\s*[\/\w]/,
    // Environment variables
    /\$\{?\w+\}?/,
    /%\w+%/,
    // Null byte injection
    /\x00|%00/
  ];

  // Enhanced Path Traversal patterns
  private pathTraversalPatterns = [
    // Standard traversal
    /\.\.[\/\\]/,
    /\.\.[\/\\]\.\.[\/\\]/,
    // URL encoded
    /%2e%2e[\/\\]/i,
    /%252e%252e[\/\\]/i, // Double encoded
    /%c0%ae%c0%ae[\/\\]/i, // Overlong UTF-8
    /\.\.[%]{2}[f5c][\/\\]/i,
    // Unicode variations
    /\u002e\u002e[\/\\]/,
    /\uff0e\uff0e[\/\\]/,
    // Sensitive paths
    /(\/|\\)(etc|windows|system32|boot|proc|sys|var|usr|opt|home|root)/i,
    // Windows drive letters
    /[a-zA-Z]:[\/\\]/,
    // Null bytes
    /\0|%00/,
    // UNC paths
    /\\\\[^\\]+\\/,
    // Absolute paths
    /^\/[a-z]/i,
    // Multiple slashes
    /[\/\\]{2,}/
  ];

  // Enhanced XXE patterns
  private xxePatterns = [
    // Entity declarations
    /<!ENTITY/i,
    /<!DOCTYPE/i,
    // External references
    /SYSTEM\s+["']/i,
    /PUBLIC\s+["']/i,
    // Parameter entities
    /%\w+;/,
    // External DTD
    /<!ELEMENT/i,
    /<!ATTLIST/i,
    // Common XXE payloads
    /file:\/\//i,
    /php:\/\//i,
    /expect:\/\//i,
    /data:\/\//i,
    // XML processing instructions
    /<\?xml[^>]*>/i,
    // XSLT attacks
    /<xsl:/i
  ];

  // Enhanced SSRF patterns
  private ssrfPatterns = [
    // Localhost variations
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /0x7f\.0\.0\.1/,
    /0x7f000001/,
    /2130706433/, // Decimal representation of 127.0.0.1
    /017700000001/, // Octal
    // IPv6 localhost
    /::1/,
    /::ffff:127\.0\.0\.1/,
    /0:0:0:0:0:0:0:1/,
    // Link-local
    /169\.254\./,
    /fe80:/i,
    // Private IP ranges
    /192\.168\./,
    /10\./,
    /172\.(1[6-9]|2[0-9]|3[0-1])\./,
    // Cloud metadata endpoints
    /169\.254\.169\.254/,
    /metadata\.google\.internal/i,
    /metadata\.azure/i,
    // URL credentials
    /@/,
    // DNS rebinding
    /\d+\.\d+\.\d+\.\d+\.xip\.io/i,
    /\d+\.\d+\.\d+\.\d+\.nip\.io/i,
    // URL encoding tricks
    /%32%35%35/i,
    // File protocols
    /file:\/\//i,
    /gopher:\/\//i,
    /dict:\/\//i,
    /ftp:\/\//i,
    /tftp:\/\//i
  ];

  // Whitelist for legitimate inputs to reduce false positives
  private whitelistPatterns = [
    // Common safe SQL patterns
    /^[a-zA-Z0-9_@.-]+$/,
    // Email addresses
    /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    // URLs (when not in path context)
    /^https?:\/\/[a-zA-Z0-9.-]+/
  ];

  detect(input: any, context: string = 'unknown'): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    
    if (!input) return threats;

    const inputs = this.extractInputs(input);

    for (const value of inputs) {
      if (typeof value !== 'string') continue;

      // Skip if value matches whitelist (reduce false positives)
      if (this.isWhitelisted(value, context)) continue;

      // SQL Injection detection with confidence scoring
      const sqlMatches = this.sqlPatterns.filter(pattern => pattern.test(value));
      if (sqlMatches.length > 0) {
        threats.push({
          type: ThreatType.SQL_INJECTION,
          severity: sqlMatches.length >= 3 ? 'critical' : 'high',
          description: `Potential SQL injection detected (confidence: ${this.calculateConfidence(sqlMatches.length, this.sqlPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: sqlMatches.length,
            confidence: this.calculateConfidence(sqlMatches.length, this.sqlPatterns.length)
          }
        });
      }

      // NoSQL Injection detection with confidence scoring
      const nosqlMatches = this.nosqlPatterns.filter(pattern => pattern.test(value));
      if (nosqlMatches.length > 0) {
        threats.push({
          type: ThreatType.NOSQL_INJECTION,
          severity: nosqlMatches.length >= 2 ? 'critical' : 'high',
          description: `Potential NoSQL injection detected (confidence: ${this.calculateConfidence(nosqlMatches.length, this.nosqlPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: nosqlMatches.length,
            confidence: this.calculateConfidence(nosqlMatches.length, this.nosqlPatterns.length)
          }
        });
      }

      // Command Injection detection with confidence scoring
      const cmdMatches = this.commandPatterns.filter(pattern => pattern.test(value));
      if (cmdMatches.length > 0) {
        threats.push({
          type: ThreatType.COMMAND_INJECTION,
          severity: 'critical',
          description: `Potential command injection detected (confidence: ${this.calculateConfidence(cmdMatches.length, this.commandPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: cmdMatches.length,
            confidence: this.calculateConfidence(cmdMatches.length, this.commandPatterns.length)
          }
        });
      }

      // Path Traversal detection with confidence scoring
      const pathMatches = this.pathTraversalPatterns.filter(pattern => pattern.test(value));
      if (pathMatches.length > 0) {
        threats.push({
          type: ThreatType.PATH_TRAVERSAL,
          severity: pathMatches.length >= 2 ? 'critical' : 'high',
          description: `Potential path traversal detected (confidence: ${this.calculateConfidence(pathMatches.length, this.pathTraversalPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: pathMatches.length,
            confidence: this.calculateConfidence(pathMatches.length, this.pathTraversalPatterns.length)
          }
        });
      }

      // XXE detection with confidence scoring
      const xxeMatches = this.xxePatterns.filter(pattern => pattern.test(value));
      if (xxeMatches.length > 0) {
        threats.push({
          type: ThreatType.XXE,
          severity: xxeMatches.length >= 2 ? 'critical' : 'high',
          description: `Potential XXE attack detected (confidence: ${this.calculateConfidence(xxeMatches.length, this.xxePatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: xxeMatches.length,
            confidence: this.calculateConfidence(xxeMatches.length, this.xxePatterns.length)
          }
        });
      }

      // SSRF detection with confidence scoring
      const ssrfMatches = this.ssrfPatterns.filter(pattern => pattern.test(value));
      if (ssrfMatches.length > 0) {
        threats.push({
          type: ThreatType.SSRF,
          severity: ssrfMatches.length >= 2 ? 'high' : 'medium',
          description: `Potential SSRF attack detected (confidence: ${this.calculateConfidence(ssrfMatches.length, this.ssrfPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            matchCount: ssrfMatches.length,
            confidence: this.calculateConfidence(ssrfMatches.length, this.ssrfPatterns.length)
          }
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

  /**
   * Calculate confidence score (0-100) based on pattern matches
   */
  private calculateConfidence(matches: number, totalPatterns: number): string {
    const percentage = Math.min((matches / Math.max(totalPatterns * 0.3, 1)) * 100, 100);
    return `${Math.round(percentage)}%`;
  }

  /**
   * Check if value matches whitelist patterns to reduce false positives
   */
  private isWhitelisted(value: string, context: string): boolean {
    // Context-specific whitelisting
    if (context === 'email' || context === 'username') {
      return this.whitelistPatterns.some(pattern => pattern.test(value));
    }
    
    // Don't whitelist suspicious contexts
    if (context === 'query' || context === 'body' || context === 'path') {
      return false;
    }

    return false;
  }
}
