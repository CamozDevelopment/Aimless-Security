import { ThreatType, SecurityThreat } from '../types';

export class XSSDetector {
  // Enhanced XSS patterns - more comprehensive detection
  private xssPatterns = [
    // Script tags
    /<script[^>]*>.*?<\/script>/is,
    /<script[^>]*>/i,
    // Iframe and embed
    /<iframe[^>]*>/i,
    /<embed[^>]*>/i,
    /<object[^>]*>/i,
    /<applet[^>]*>/i,
    // JavaScript protocols
    /javascript:/i,
    /vbscript:/i,
    /data:text\/html/i,
    /data:text\/javascript/i,
    // Event handlers (comprehensive list)
    /on(load|error|click|mouseover|mouseout|mouseenter|mouseleave|focus|blur|change|submit|keydown|keyup|keypress|dblclick|contextmenu|drag|drop|copy|paste|cut|resize|scroll|wheel|touchstart|touchend|touchmove|animationstart|animationend|transitionend)\s*=/i,
    // Dangerous attributes
    /<img[^>]+src\s*=\s*["']?javascript:/i,
    /<img[^>]+src\s*=\s*["']?data:/i,
    /<img[^>]*onerror/i,
    // JavaScript execution
    /eval\s*\(/i,
    /expression\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /Function\s*\(/i,
    // SVG-based XSS
    /<svg[^>]*onload/i,
    /<svg[^>]*>.*?<script/is,
    /<animatetransform[^>]*onbegin/i,
    // Form-based XSS
    /<form[^>]*action\s*=\s*["']?javascript:/i,
    /<button[^>]*formaction\s*=\s*["']?javascript:/i,
    // Meta refresh
    /<meta[^>]*http-equiv\s*=\s*["']?refresh/i,
    // Link href
    /<link[^>]*href\s*=\s*["']?javascript:/i,
    // Base tag
    /<base[^>]*href/i,
    // Style-based XSS
    /<style[^>]*>.*?(expression|behavior|binding|import|@import)/is,
    /style\s*=\s*["'][^"']*expression\s*\(/i,
    /style\s*=\s*["'][^"']*behavior:/i,
    // DOM-based XSS indicators
    /document\.(write|writeln|cookie|location|domain)/i,
    /window\.(location|name|open)/i,
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    // Template injection
    /\{\{.*\}\}/,
    /\$\{.*\}/,
    /<\%.*\%>/,
    // AngularJS/Vue/React XSS
    /ng-bind-html/i,
    /v-html/i,
    /dangerouslySetInnerHTML/i
  ];

  // Enhanced HTML entity encoded patterns
  private encodedPatterns = [
    // Decimal entities
    /&#\d+;/,
    // Hex entities
    /&#x[0-9a-f]+;/i,
    // URL encoding
    /%3C/i, // <
    /%3E/i, // >
    /%22/i, // "
    /%27/i, // '
    /%2F/i, // /
    /%3D/i, // =
    // Unicode encoding
    /\\u[0-9a-f]{4}/i,
    /\\x[0-9a-f]{2}/i,
    // Double encoding
    /%253C/i,
    /%253E/i,
    // Overlong UTF-8
    /%c0%bc/i,
    /%e0%80%bc/i,
    // HTML5 entities
    /&lt;/i,
    /&gt;/i,
    /&quot;/i,
    /&apos;/i,
    /&sol;/i
  ];

  // Context-aware sanitization rules
  private readonly contextRules = {
    html: ['<', '>', '&', '"', "'", '/'],
    attribute: ['"', "'", '<', '>', '&'],
    javascript: ['<', '>', '&', '"', "'", '/', '\\', '\n', '\r'],
    css: ['<', '>', '"', "'", '&', '(', ')', '{', '}'],
    url: ['javascript:', 'data:', 'vbscript:', '<', '>']
  };

  detect(input: any, context: string = 'unknown'): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    
    if (!input) return threats;

    const inputs = this.extractInputs(input);

    for (const value of inputs) {
      if (typeof value !== 'string') continue;

      // Direct XSS detection with confidence scoring
      const directMatches = this.xssPatterns.filter(pattern => pattern.test(value));
      if (directMatches.length > 0) {
        threats.push({
          type: ThreatType.XSS,
          severity: directMatches.length >= 3 ? 'critical' : 'high',
          description: `Potential XSS attack detected (confidence: ${this.calculateConfidence(directMatches.length)})`,
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { 
            context, 
            type: 'direct',
            matchCount: directMatches.length,
            confidence: this.calculateConfidence(directMatches.length)
          }
        });
      }

      // Encoded XSS detection (multi-layer decoding)
      const decoded = this.decodeInputMultiLayer(value);
      if (decoded !== value) {
        const encodedMatches = this.xssPatterns.filter(pattern => pattern.test(decoded));
        if (encodedMatches.length > 0) {
          threats.push({
            type: ThreatType.XSS,
            severity: encodedMatches.length >= 3 ? 'critical' : 'high',
            description: `Potential encoded XSS attack detected (confidence: ${this.calculateConfidence(encodedMatches.length)})`,
            payload: value,
            timestamp: new Date(),
            blocked: true,
            metadata: { 
              context, 
              type: 'encoded', 
              decoded,
              matchCount: encodedMatches.length,
              confidence: this.calculateConfidence(encodedMatches.length)
            }
          });
        }
      }

      // Mutation XSS detection (mXSS)
      if (this.detectMutationXSS(value)) {
        threats.push({
          type: ThreatType.XSS,
          severity: 'high',
          description: 'Potential mutation XSS (mXSS) detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context, type: 'mutation' }
        });
      }
    }

    return threats;
  }

  /**
   * Multi-layer decoding to catch deeply encoded attacks
   */
  private decodeInputMultiLayer(input: string, maxDepth: number = 3): string {
    let decoded = input;
    let previousDecoded = '';
    let depth = 0;

    while (decoded !== previousDecoded && depth < maxDepth) {
      previousDecoded = decoded;
      decoded = this.decodeInput(decoded);
      depth++;
    }

    return decoded;
  }

  private decodeInput(input: string): string {
    let decoded = input;
    
    try {
      // HTML entity decoding
      decoded = decoded.replace(/&#(\d+);/g, (_, num) => String.fromCharCode(parseInt(num)));
      decoded = decoded.replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      
      // Named HTML entities
      decoded = decoded.replace(/&lt;/gi, '<');
      decoded = decoded.replace(/&gt;/gi, '>');
      decoded = decoded.replace(/&quot;/gi, '"');
      decoded = decoded.replace(/&apos;/gi, "'");
      decoded = decoded.replace(/&amp;/gi, '&');
      decoded = decoded.replace(/&sol;/gi, '/');
      
      // URL decoding
      decoded = decodeURIComponent(decoded);
      
      // Unicode decoding
      decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      
      // Overlong UTF-8
      decoded = decoded.replace(/%c0%bc/gi, '<');
      decoded = decoded.replace(/%e0%80%bc/gi, '<');
    } catch (e) {
      // Decoding failed, return original
    }

    return decoded;
  }

  /**
   * Detect mutation XSS (mXSS) attempts
   */
  private detectMutationXSS(input: string): boolean {
    const mxssPatterns = [
      // Backtick-based mXSS
      /<[^>]*`[^>]*>/,
      // SVG mXSS
      /<svg><style>.*@import/i,
      // Namespace confusion
      /<math><mi xlink:href/i,
      // Form mXSS
      /<form><math><mtext><\/form><form>/i,
      // Select mXSS
      /<select><\/select><img src=x onerror/i,
      // Noscript mXSS
      /<noscript><style>.*<\/style><\/noscript>/i
    ];

    return mxssPatterns.some(pattern => pattern.test(input));
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
        inputs.push(...this.extractInputs(input[key]));
      }
    }

    return inputs;
  }

  /**
   * Calculate confidence score for XSS detection
   */
  private calculateConfidence(matches: number): string {
    const percentage = Math.min((matches / 3) * 100, 100);
    return `${Math.round(percentage)}%`;
  }

  /**
   * Context-aware sanitization
   */
  sanitize(input: string, context: 'html' | 'attribute' | 'javascript' | 'css' | 'url' = 'html'): string {
    if (context === 'html') {
      return this.sanitizeHTML(input);
    } else if (context === 'attribute') {
      return this.sanitizeAttribute(input);
    } else if (context === 'javascript') {
      return this.sanitizeJavaScript(input);
    } else if (context === 'css') {
      return this.sanitizeCSS(input);
    } else if (context === 'url') {
      return this.sanitizeURL(input);
    }
    return this.sanitizeHTML(input);
  }

  /**
   * Basic HTML sanitization
   */
  private sanitizeHTML(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Sanitize for HTML attributes
   */
  private sanitizeAttribute(input: string): string {
    return input
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/&/g, '&amp;');
  }

  /**
   * Sanitize for JavaScript contexts
   */
  private sanitizeJavaScript(input: string): string {
    return input
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/</g, '\\x3C')
      .replace(/>/g, '\\x3E')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }

  /**
   * Sanitize for CSS contexts
   */
  private sanitizeCSS(input: string): string {
    // Only allow alphanumeric and safe characters
    return input.replace(/[^a-zA-Z0-9\s\-_#.]/g, '');
  }

  /**
   * Sanitize URLs
   */
  private sanitizeURL(input: string): string {
    const dangerous = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:'];
    const lower = input.toLowerCase();
    
    if (dangerous.some(protocol => lower.includes(protocol))) {
      return '';
    }
    
    return encodeURI(input);
  }
}
