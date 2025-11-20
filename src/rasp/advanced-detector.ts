import { ThreatType, SecurityThreat } from '../types';

export class AdvancedThreatDetector {
  /**
   * LDAP Injection Detection
   */
  private ldapPatterns = [
    // LDAP filter injection
    /\*\(/,
    /\)\(/,
    /\|/,
    /&\(/,
    // LDAP special characters
    /[\(\)\*\|\&]/,
    // Common LDAP attributes
    /\b(cn|uid|ou|dc|objectClass|mail|sn|givenName)=/i,
    // LDAP wildcards
    /\*\*+/,
    // LDAP operators
    /[<>]=?/,
    // Null byte injection in LDAP
    /\x00/,
    // LDAP comment
    /\(\|/,
    // Bypass patterns
    /\)\(\|/,
    /\*\)\(uid=/i,
    // Admin bypass
    /admin\)\(/i,
    /\*\)\(objectClass=\*/i
  ];

  /**
   * Template Injection Detection (SSTI/CSTI)
   */
  private templatePatterns = [
    // Jinja2/Flask
    /\{\{.*config/i,
    /\{\{.*\.__class__/,
    /\{\{.*\.__mro__/,
    /\{\{.*\.__subclasses__/,
    /\{\{.*\.__globals__/,
    /\{\{.*\.__builtins__/,
    // Django
    /\{\%\s*load/i,
    /\{\%\s*debug/i,
    // Twig
    /\{\{.*_self\.env/i,
    // Smarty
    /\{php\}/i,
    /\{literal\}/i,
    // Freemarker
    /<#assign/i,
    /<#import/i,
    // Velocity
    /#set\s*\(/i,
    // Thymeleaf
    /\$\{T\(/i,
    /__\${/,
    // General template syntax
    /\$\{.*Runtime/i,
    /\$\{.*ProcessBuilder/i,
    /\{\{.*eval/i,
    /\{\{.*exec/i,
    // Ruby ERB
    /<%=.*system/i,
    /<%=.*eval/i,
    // Pug/Jade
    /-\s*var.*require/i
  ];

  /**
   * File Upload Security Patterns
   */
  private fileUploadPatterns = [
    // Dangerous extensions
    /\.(php|phtml|php3|php4|php5|phps|pht|phar)$/i,
    /\.(jsp|jspx|jsw|jsv|jspf)$/i,
    /\.(asp|aspx|asa|asax|ascx|ashx|asmx|cer|aSp|aSpx)$/i,
    /\.(exe|dll|bat|cmd|com|scr|vbs|js|jar|msi)$/i,
    /\.(sh|bash|zsh|csh|ksh|fish)$/i,
    /\.(pl|py|rb|go|ps1)$/i,
    // Double extensions
    /\.jpg\.php$/i,
    /\.png\.jsp$/i,
    /\.pdf\.exe$/i,
    // Null byte
    /\.php%00\.jpg/i,
    /\.jsp\x00\.png/i,
    // MIME type mismatches
    /^Content-Type:.*application\/(x-php|x-httpd-php)/i,
    // Polyglot files
    /GIF89a.*<\?php/i,
    /PNG.*<script/i,
    // Web shells signatures
    /passthru\s*\(/i,
    /shell_exec\s*\(/i,
    /system\s*\(/i,
    /phpinfo\s*\(/i,
    /base64_decode.*eval/i,
    /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.*eval/i,
    // HTAccess manipulation
    /AddType.*php/i,
    /SetHandler.*php/i
  ];

  /**
   * JWT Security Issues
   */
  private jwtPatterns = [
    // Weak algorithms
    /"alg"\s*:\s*"none"/i,
    /"alg"\s*:\s*"HS256"/i,
    // Algorithm confusion
    /"alg"\s*:\s*"RS256".*"typ"\s*:\s*"JWT"/i,
    // Empty or weak keys
    /"k"\s*:\s*""/i,
    /"k"\s*:\s*"123/i,
    // Token manipulation
    /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\./,
    // SQL injection in JWT
    /eyJ.*J9\./,
    // Infinite expiration
    /"exp"\s*:\s*9999999999/i,
    /"exp"\s*:\s*null/i
  ];

  /**
   * GraphQL Security Patterns
   */
  private graphqlPatterns = [
    // Introspection queries
    /__schema/i,
    /__type/i,
    /IntrospectionQuery/i,
    // Deeply nested queries (DOS)
    /\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{/,
    // Circular references
    /query.*\$.*query/i,
    // Batch attacks
    /query.*query.*query/i,
    // Alias abuse
    /alias\d+:/i,
    // Fragment spreading
    /\.\.\.on/i,
    // Directive abuse
    /@include.*@include/i,
    /@skip.*@skip/i,
    // Field duplication
    /(\w+)\s*\{[^}]*\1\s*\{/
  ];

  /**
   * XML External Entity (XXE) - Enhanced
   */
  private xxePatterns = [
    // DOCTYPE declarations
    /<!DOCTYPE[^>]*\[/i,
    // ENTITY declarations
    /<!ENTITY[^>]*>/i,
    // SYSTEM keyword
    /SYSTEM\s+["'][^"']*["']/i,
    // PUBLIC keyword  
    /PUBLIC\s+["'][^"']*["']/i,
    // Parameter entities
    /<!ENTITY\s+%/i,
    /%\w+;/,
    // External DTD
    /<!ELEMENT/i,
    /<!ATTLIST/i,
    // Common XXE payloads
    /file:\/\//i,
    /php:\/\//i,
    /expect:\/\//i,
    /data:\/\//i,
    /jar:\/\//i,
    /gopher:\/\//i,
    // Wrapper protocols
    /zip:\/\//i,
    /compress\.zlib:\/\//i,
    // XML Bomb
    /<!ENTITY\s+\w+\s+"&\w+;/i,
    // Billion Laughs
    /lol\d+/i
  ];

  /**
   * Server-Side Request Forgery (SSRF) - Enhanced
   */
  private ssrfPatterns = [
    // Cloud metadata endpoints
    /169\.254\.169\.254/,
    /metadata\.google\.internal/i,
    /169\.254\.170\.2/,
    /metadata\.azure/i,
    /100\.100\.100\.200/,
    // localhost variations
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /0x7f\.0\.0\.1/,
    /0x7f000001/,
    /2130706433/,
    /017700000001/,
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
    // DNS rebinding
    /\d+\.\d+\.\d+\.\d+\.xip\.io/i,
    /\d+\.\d+\.\d+\.\d+\.nip\.io/i,
    /\d+\.\d+\.\d+\.\d+\.sslip\.io/i,
    // URL parsing bypass
    /@127\.0\.0\.1/,
    /@localhost/i,
    // Scheme manipulation
    /file:\/\//i,
    /gopher:\/\//i,
    /dict:\/\//i,
    /ftp:\/\//i,
    /tftp:\/\//i,
    /ldap:\/\//i,
    // URL encoding bypass
    /%32%35%35/i,
    /%31%32%37/i,
    // Unicode bypass
    /\u0031\u0032\u0037/,
    // CRLF injection
    /%0d%0a/i,
    /\r\n/
  ];

  /**
   * Prototype Pollution Detection
   */
  private prototypePollutionPatterns = [
    /__proto__/,
    /constructor\.prototype/i,
    /\["__proto__"\]/,
    /\['__proto__'\]/,
    /\[constructor\]/i,
    /\.constructor\.prototype/i,
    // JSON-based
    /\{"__proto__"/,
    /\{'__proto__'/,
    // Deep merge vulnerability
    /Object\.assign.*__proto__/i,
    /\$\.extend.*__proto__/i,
    /lodash\.merge.*__proto__/i
  ];

  /**
   * Deserialization Attacks
   */
  private deserializationPatterns = [
    // Java deserialization
    /rO0AB/,
    /aced0005/i,
    /java\.lang\.Runtime/i,
    /java\.lang\.ProcessBuilder/i,
    // Python pickle
    /\x80\x03/,
    /pickle\.loads/i,
    /cPickle\.loads/i,
    // PHP unserialize
    /O:\d+:"[^"]*":\d+:\{/,
    /a:\d+:\{/,
    // .NET
    /\$type.*System\.Windows\.Data\.ObjectDataProvider/i,
    /\$type.*System\.Diagnostics\.Process/i,
    // Ruby Marshal
    /\x04\x08/,
    // Node.js
    /node-serialize/i,
    /_$$ND_FUNC$$_/
  ];

  /**
   * Detect LDAP injection
   */
  detectLDAPInjection(input: string): SecurityThreat | null {
    const matches = this.ldapPatterns.filter(pattern => pattern.test(input));
    
    if (matches.length >= 2) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'high',
        description: 'Potential LDAP injection detected',
        payload: input,
        timestamp: new Date(),
        blocked: true,
        confidence: matches.length >= 3 ? 85 : 60,
        metadata: {
          type: 'ldap_injection',
          matchCount: matches.length
        }
      };
    }
    
    return null;
  }

  /**
   * Detect template injection
   */
  detectTemplateInjection(input: string): SecurityThreat | null {
    const matches = this.templatePatterns.filter(pattern => pattern.test(input));
    
    if (matches.length > 0) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Potential Server-Side Template Injection (SSTI) detected',
        payload: input,
        timestamp: new Date(),
        blocked: true,
        confidence: matches.length >= 2 ? 90 : 70,
        metadata: {
          type: 'template_injection',
          matchCount: matches.length
        }
      };
    }
    
    return null;
  }

  /**
   * Validate file upload security
   */
  validateFileUpload(filename: string, content?: string, mimeType?: string): SecurityThreat | null {
    const threats: string[] = [];
    
    // Check filename
    const filenameMatches = this.fileUploadPatterns.filter(pattern => pattern.test(filename));
    if (filenameMatches.length > 0) {
      threats.push('dangerous_filename');
    }
    
    // Check content if provided
    if (content) {
      const contentMatches = this.fileUploadPatterns.filter(pattern => pattern.test(content));
      if (contentMatches.length > 0) {
        threats.push('malicious_content');
      }
    }
    
    // Check MIME type mismatch
    if (mimeType && /\.(jpg|png|gif)$/i.test(filename) && !/^image\//i.test(mimeType)) {
      threats.push('mime_mismatch');
    }
    
    if (threats.length > 0) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Malicious file upload detected',
        payload: filename,
        timestamp: new Date(),
        blocked: true,
        confidence: 90,
        metadata: {
          type: 'file_upload',
          threats
        }
      };
    }
    
    return null;
  }

  /**
   * Analyze JWT token security
   */
  analyzeJWT(token: string): SecurityThreat | null {
    try {
      // Decode JWT header and payload
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const header = Buffer.from(parts[0], 'base64').toString();
      const payload = Buffer.from(parts[1], 'base64').toString();
      
      const matches = this.jwtPatterns.filter(pattern => 
        pattern.test(header) || pattern.test(payload)
      );
      
      if (matches.length > 0) {
        return {
          type: ThreatType.ANOMALOUS_BEHAVIOR,
          severity: 'high',
          description: 'Insecure JWT token detected',
          payload: header,
          timestamp: new Date(),
          blocked: true,
          confidence: 85,
          metadata: {
            type: 'jwt_security',
            matchCount: matches.length
          }
        };
      }
    } catch (error) {
      // Invalid JWT format
    }
    
    return null;
  }

  /**
   * Detect GraphQL attacks
   */
  detectGraphQLAttack(query: string): SecurityThreat | null {
    const matches = this.graphqlPatterns.filter(pattern => pattern.test(query));
    
    if (matches.length > 0) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: matches.length >= 2 ? 'high' : 'medium',
        description: 'Potential GraphQL attack detected',
        payload: query.substring(0, 100),
        timestamp: new Date(),
        blocked: true,
        confidence: matches.length >= 2 ? 80 : 60,
        metadata: {
          type: 'graphql_attack',
          matchCount: matches.length
        }
      };
    }
    
    return null;
  }

  /**
   * Detect prototype pollution
   */
  detectPrototypePollution(input: any): SecurityThreat | null {
    const str = JSON.stringify(input);
    const matches = this.prototypePollutionPatterns.filter(pattern => pattern.test(str));
    
    if (matches.length > 0) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Prototype pollution attempt detected',
        payload: str.substring(0, 100),
        timestamp: new Date(),
        blocked: true,
        confidence: 95,
        metadata: {
          type: 'prototype_pollution',
          matchCount: matches.length
        }
      };
    }
    
    return null;
  }

  /**
   * Detect deserialization attacks
   */
  detectDeserialization(input: string): SecurityThreat | null {
    const matches = this.deserializationPatterns.filter(pattern => pattern.test(input));
    
    if (matches.length > 0) {
      return {
        type: ThreatType.ANOMALOUS_BEHAVIOR,
        severity: 'critical',
        description: 'Insecure deserialization detected',
        payload: input.substring(0, 100),
        timestamp: new Date(),
        blocked: true,
        confidence: 90,
        metadata: {
          type: 'deserialization',
          matchCount: matches.length
        }
      };
    }
    
    return null;
  }

  /**
   * Comprehensive advanced threat detection
   */
  detectAll(input: any, context?: string): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    const str = typeof input === 'string' ? input : JSON.stringify(input);
    
    // LDAP injection
    const ldap = this.detectLDAPInjection(str);
    if (ldap) threats.push(ldap);
    
    // Template injection
    const template = this.detectTemplateInjection(str);
    if (template) threats.push(template);
    
    // Prototype pollution
    const proto = this.detectPrototypePollution(input);
    if (proto) threats.push(proto);
    
    // Deserialization
    const deser = this.detectDeserialization(str);
    if (deser) threats.push(deser);
    
    // JWT (if looks like a token)
    if (str.match(/^eyJ[a-zA-Z0-9_-]+\./)) {
      const jwt = this.analyzeJWT(str);
      if (jwt) threats.push(jwt);
    }
    
    // GraphQL (if context suggests GraphQL)
    if (context === 'graphql' || str.includes('query') || str.includes('mutation')) {
      const graphql = this.detectGraphQLAttack(str);
      if (graphql) threats.push(graphql);
    }
    
    return threats;
  }
}
