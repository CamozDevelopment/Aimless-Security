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
    // Classic tautologies
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /"\s*OR\s*"1"\s*=\s*"1/i,
    /'\s*OR\s*1\s*=\s*1/i,
    /'\s*AND\s*'1'\s*=\s*'1/i,
    // Admin bypass patterns
    /admin'\s*(--|#|\/\*)/i,
    /'\s*OR\s*'a'\s*=\s*'a/i,
    // SQL comments and terminators
    /(--|#|\/\*|\*\/|;)\s*$/,
    /';?\s*(--|#)/,
    // Union-based injections
    /(\bUNION\b\s+(ALL\s+)?SELECT\b)/i,
    /\bUNION\b.*\bSELECT\b/i,
    // Quote manipulation
    /('|")\s*(OR|AND)\s*('|")\s*=\s*('|")/i,
    // Hex encoding
    /(0x[0-9a-fA-F]{2,})/,
    // SQL functions
    /(\b(CHAR|CONCAT|SUBSTRING|ASCII|ORD|HEX|UNHEX|BENCHMARK|SLEEP|WAITFOR|DELAY|LOAD_FILE|INTO\s+OUTFILE)\b\s*\()/i,
    // Stored procedures
    /\b(xp_|sp_)\w+/i,
    // Stacked queries
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)/i,
    // Time-based blind injection
    /\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep|DBMS_LOCK\.SLEEP)\b/i,
    // Error-based injection
    /\b(EXTRACTVALUE|UPDATEXML|EXP|POW|FLOOR|RAND|GROUP_CONCAT)\b\s*\(/i,
    // Information schema access
    /\b(information_schema|sys\.|mysql\.|performance_schema|pg_catalog)\b/i,
    // Boolean-based blind
    /\b(CASE|IF|IIF|CHOOSE)\b\s*\(/i,
    // Database version fingerprinting
    /\b(@@version|version\(\)|sqlite_version|pg_version)\b/i,
    // Database user extraction
    /\b(user\(\)|current_user|session_user|system_user)\b/i,
    // NULL byte injection in SQL
    /\x00/,
    // SQL wildcards in suspicious contexts
    /[%_]\s*['"]?\s*(OR|AND)\s*['"]?/i,
    // Multi-line comment injection
    /\/\*.*?\*\//s
  ];

  // Enhanced NoSQL Injection patterns
  private nosqlPatterns = [
    // MongoDB operators
    /\$where/i,
    /\$(ne|eq|gt|gte|lt|lte|in|nin|regex|exists|type|mod|text|all|elemMatch|size|slice)/i,
    // Object notation
    /\{\s*['"]\$[a-z]+['"]\s*:/i,
    // JavaScript injection in MongoDB
    /\bthis\b\s*\.\s*\w+/,
    /\bfunction\s*\(/,
    /\beval\s*\(/,
    /constructor\s*\(/i,
    // NoSQL aggregation
    /\$(match|group|project|lookup|unwind|sort|limit|skip|count|addFields|replaceRoot)/i,
    // CouchDB/PouchDB
    /_design\//,
    /_view\//,
    /_all_docs/i,
    // Redis commands
    /\b(FLUSHALL|FLUSHDB|CONFIG|EVAL|SCRIPT|KEYS|DEL|SET|GET|APPEND)\b/i,
    // Cassandra CQL
    /\b(ALLOW\s+FILTERING|BATCH|TRUNCATE)\b/i,
    // NoSQL injection via array
    /\[\s*\{\s*['"]\$/,
    // MongoDB mapReduce injection
    /\b(mapReduce|map|reduce|finalize)\b/i,
    // Prototype pollution
    /__proto__/,
    /constructor\.prototype/i,
    // Server-side JavaScript
    /process\./,
    /require\s*\(/,
    /global\./,
    // MongoDB $function operator
    /\$function/i
  ];

  // Enhanced Command Injection patterns
  private commandPatterns = [
    // Command separators and operators
    /[;&|`$(){}[\]<>]/,
    /(\|\||&&)/,
    // Common Unix/Linux commands
    /\b(cat|ls|dir|pwd|cd|echo|printf|ping|whoami|id|uname|wget|curl|nc|netcat|ncat|bash|sh|zsh|csh|ksh|find|grep|awk|sed|chmod|chown|kill|ps|top|df|du|mount|umount|dd)\b/i,
    // Common Windows commands
    /\b(cmd|powershell|pwsh|wmic|reg|sc|net|tasklist|taskkill|ipconfig|systeminfo|type|copy|move|del|rd|mkdir)\b/i,
    // Path traversal in commands
    /(\.\.[\/\\]|~\/)/,
    // Newline injections
    /(\r\n|\n|\r|%0a|%0d)/,
    // Backticks and command substitution
    /`[^`]*`/,
    /\$\([^)]*\)/,
    // PowerShell specific
    /\b(Invoke-Expression|IEX|Invoke-Command|ICM|Get-Content|GC|Start-Process|Stop-Process|Get-Process)\b/i,
    // File redirection
    /[><]{1,2}\s*[\/\w.]/,
    // Environment variables
    /\$\{?\w+\}?/,
    /%\w+%/,
    // Null byte injection
    /\x00|%00/,
    // SSH and network commands
    /\b(ssh|scp|sftp|telnet|ftp|tftp|rsync)\b/i,
    // File manipulation
    /\b(tar|gzip|gunzip|zip|unzip|bzip2|7z|rar)\b/i,
    // Process control
    /\b(nohup|screen|tmux|disown|jobs|fg|bg)\b/i,
    // Package managers
    /\b(apt|apt-get|yum|dnf|pacman|brew|npm|pip|gem|cargo)\b/i,
    // Text editors (can be used for file manipulation)
    /\b(vi|vim|nano|emacs|pico)\b/i,
    // Reverse shells
    /\b(socat|perl|python|ruby|php|node)\b.*-e/i,
    // Base64 encoded commands
    /base64.*-d/i,
    // Compression and archiving with command execution
    /\|\s*(sh|bash|zsh|ksh|csh)/i
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
    // Common safe patterns
    /^[a-zA-Z0-9_@.-]+$/,
    // Email addresses
    /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    // UUIDs
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    // ISO dates
    /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?)?$/,
    // Simple numbers
    /^\d+$/,
    /^\d+\.\d+$/,
    // Common safe strings (alphanumeric with spaces)
    /^[a-zA-Z0-9\s]+$/
  ];

  // Context-specific safe patterns
  private contextWhitelist: Record<string, RegExp[]> = {
    email: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/],
    username: [/^[a-zA-Z0-9_.-]{3,30}$/],
    name: [/^[a-zA-Z\s'-]{1,50}$/],
    uuid: [/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i],
    date: [/^\d{4}-\d{2}-\d{2}$/],
    url: [/^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/],
    number: [/^\d+$/, /^\d+\.\d+$/],
    alphanumeric: [/^[a-zA-Z0-9]+$/]
  };

  detect(input: any, context: string = 'unknown'): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    
    if (!input) return threats;

    const inputs = this.extractInputs(input);

    for (const value of inputs) {
      if (typeof value !== 'string') continue;

      // Skip very short or very long inputs (likely false positives or DOS attempts)
      if (value.length < 2 || value.length > 10000) continue;

      // Skip if value matches whitelist (reduce false positives)
      if (this.isWhitelisted(value, context)) continue;

      // Skip common safe values
      if (this.isSafeValue(value)) continue;

      // SQL Injection detection with confidence scoring
      const sqlMatches = this.sqlPatterns.filter(pattern => pattern.test(value));
      if (sqlMatches.length > 0) {
        // Require at least 2 pattern matches to reduce false positives
        if (sqlMatches.length >= 2 || this.hasHighConfidenceSQLPattern(value)) {
          threats.push({
            type: ThreatType.SQL_INJECTION,
            severity: sqlMatches.length >= 3 ? 'critical' : 'high',
            description: `Potential SQL injection detected (confidence: ${this.calculateConfidence(sqlMatches.length, this.sqlPatterns.length)})`,
            payload: value,
            timestamp: new Date(),
            blocked: true,
            confidence: this.calculateConfidenceNumber(sqlMatches.length, this.sqlPatterns.length),
            metadata: { 
              context, 
              matchCount: sqlMatches.length,
              confidence: this.calculateConfidence(sqlMatches.length, this.sqlPatterns.length)
            }
          });
        }
      }

      // NoSQL Injection detection with confidence scoring
      const nosqlMatches = this.nosqlPatterns.filter(pattern => pattern.test(value));
      if (nosqlMatches.length >= 2 || this.hasHighConfidenceNoSQLPattern(value)) {
        threats.push({
          type: ThreatType.NOSQL_INJECTION,
          severity: nosqlMatches.length >= 3 ? 'critical' : 'high',
          description: `Potential NoSQL injection detected (confidence: ${this.calculateConfidence(nosqlMatches.length, this.nosqlPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          confidence: this.calculateConfidenceNumber(nosqlMatches.length, this.nosqlPatterns.length),
          metadata: { 
            context, 
            matchCount: nosqlMatches.length,
            confidence: this.calculateConfidence(nosqlMatches.length, this.nosqlPatterns.length)
          }
        });
      }

      // Command Injection detection with confidence scoring
      const cmdMatches = this.commandPatterns.filter(pattern => pattern.test(value));
      if (cmdMatches.length >= 2 || this.hasHighConfidenceCommandPattern(value)) {
        threats.push({
          type: ThreatType.COMMAND_INJECTION,
          severity: 'critical',
          description: `Potential command injection detected (confidence: ${this.calculateConfidence(cmdMatches.length, this.commandPatterns.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          confidence: this.calculateConfidenceNumber(cmdMatches.length, this.commandPatterns.length),
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
    // More realistic confidence calculation
    // 1 match = 30%, 2 matches = 60%, 3+ matches = 90%+
    let percentage: number;
    
    if (matches === 1) {
      percentage = 30;
    } else if (matches === 2) {
      percentage = 60;
    } else if (matches === 3) {
      percentage = 85;
    } else {
      percentage = Math.min(85 + (matches - 3) * 5, 100);
    }
    
    return `${Math.round(percentage)}%`;
  }

  /**
   * Calculate numeric confidence score (0-100)
   */
  private calculateConfidenceNumber(matches: number, totalPatterns: number): number {
    if (matches === 1) {
      return 30;
    } else if (matches === 2) {
      return 60;
    } else if (matches === 3) {
      return 85;
    } else {
      return Math.min(85 + (matches - 3) * 5, 100);
    }
  }

  /**
   * Check if value contains high-confidence SQL injection patterns
   */
  private hasHighConfidenceSQLPattern(value: string): boolean {
    // These patterns are almost always malicious
    const highConfidencePatterns = [
      /'\s*OR\s*'1'\s*=\s*'1/i,
      /'\s*OR\s*1\s*=\s*1/i,
      /\bUNION\b.*\bSELECT\b/i,
      /admin'\s*(--|#)/i,
      /;\s*DROP\s+/i,
      /;\s*DELETE\s+FROM\s+/i,
      /\bEXEC\s*\(/i,
      /\bEXECUTE\s*\(/i
    ];
    
    return highConfidencePatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if value contains high-confidence NoSQL injection patterns
   */
  private hasHighConfidenceNoSQLPattern(value: string): boolean {
    const highConfidencePatterns = [
      /\$where.*function/i,
      /__proto__/,
      /constructor\.prototype/i,
      /\{\s*['"]\$ne['"]\s*:\s*null\s*\}/i,
      /process\./,
      /require\s*\(/
    ];
    
    return highConfidencePatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if value contains high-confidence command injection patterns
   */
  private hasHighConfidenceCommandPattern(value: string): boolean {
    const highConfidencePatterns = [
      /;\s*(rm|del|format|dd)\s+/i,
      /\|\s*(sh|bash|cmd|powershell)\s*$/i,
      /`.*\|/,
      /\$\(.*\|/,
      /wget.*\|/i,
      /curl.*\|/i,
      /nc\s+-e/i,
      /bash\s+-i/i
    ];
    
    return highConfidencePatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if value is a common safe value that shouldn't trigger alerts
   */
  private isSafeValue(value: string): boolean {
    // Empty or whitespace only
    if (!value || /^\s*$/.test(value)) return true;

    // Check against whitelist patterns
    if (this.whitelistPatterns.some(pattern => pattern.test(value))) return true;

    // Common safe words that might contain SQL keywords in normal text
    const safeWords = [
      'select',
      'insert',
      'update',
      'delete',
      'order',
      'sort',
      'filter',
      'search',
      'find'
    ];
    
    // If it's just a single safe word, allow it
    const lowerValue = value.toLowerCase().trim();
    if (safeWords.includes(lowerValue)) return true;

    // Check for normal prose (lots of spaces, proper capitalization)
    const wordCount = value.split(/\s+/).length;
    const hasProperSpacing = wordCount > 3 && /[a-zA-Z]\s+[a-zA-Z]/.test(value);
    const noSuspiciousChars = !/[;'"<>{}$|&`]/.test(value);
    
    if (hasProperSpacing && noSuspiciousChars) return true;

    return false;
  }

  /**
   * Check if value matches whitelist patterns to reduce false positives
   */
  private isWhitelisted(value: string, context: string): boolean {
    // Check context-specific whitelist
    if (this.contextWhitelist[context]) {
      if (this.contextWhitelist[context].some(pattern => pattern.test(value))) {
        return true;
      }
    }
    
    // Check general whitelist
    if (this.whitelistPatterns.some(pattern => pattern.test(value))) {
      return true;
    }
    
    return false;
  }
}
