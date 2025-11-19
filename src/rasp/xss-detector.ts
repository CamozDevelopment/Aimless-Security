import { ThreatType, SecurityThreat } from '../types';

export class XSSDetector {
  // XSS patterns
  private xssPatterns = [
    /<script[^>]*>.*?<\/script>/i,
    /<iframe[^>]*>/i,
    /<embed[^>]*>/i,
    /<object[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=\s*["'][^"']*["']/i,
    /<img[^>]+src\s*=\s*["']?javascript:/i,
    /eval\s*\(/i,
    /expression\s*\(/i,
    /vbscript:/i,
    /data:text\/html/i,
    /<svg[^>]*onload/i,
    /<body[^>]*onload/i,
    /onerror\s*=\s*/i,
    /onload\s*=\s*/i,
    /onclick\s*=\s*/i,
    /onmouseover\s*=\s*/i,
    /<\s*\w+[^>]*(on\w+|style\s*=)/i
  ];

  // HTML entity encoded patterns
  private encodedPatterns = [
    /&#x?[0-9a-f]+;/i,
    /%3C/i, // <
    /%3E/i, // >
    /%22/i, // "
    /%27/i, // '
    /\\u[0-9a-f]{4}/i,
    /\\x[0-9a-f]{2}/i
  ];

  detect(input: any, context: string = 'unknown'): SecurityThreat[] {
    const threats: SecurityThreat[] = [];
    
    if (!input) return threats;

    const inputs = this.extractInputs(input);

    for (const value of inputs) {
      if (typeof value !== 'string') continue;

      // Direct XSS detection
      if (this.xssPatterns.some(pattern => pattern.test(value))) {
        threats.push({
          type: ThreatType.XSS,
          severity: 'high',
          description: 'Potential XSS attack detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context, type: 'direct' }
        });
      }

      // Encoded XSS detection
      const decoded = this.decodeInput(value);
      if (decoded !== value && this.xssPatterns.some(pattern => pattern.test(decoded))) {
        threats.push({
          type: ThreatType.XSS,
          severity: 'high',
          description: 'Potential encoded XSS attack detected',
          payload: value,
          timestamp: new Date(),
          blocked: true,
          metadata: { context, type: 'encoded', decoded }
        });
      }
    }

    return threats;
  }

  private decodeInput(input: string): string {
    let decoded = input;
    
    try {
      // HTML entity decoding
      decoded = decoded.replace(/&#(\d+);/g, (_, num) => String.fromCharCode(parseInt(num)));
      decoded = decoded.replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      
      // URL decoding
      decoded = decodeURIComponent(decoded);
      
      // Unicode decoding
      decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    } catch (e) {
      // Decoding failed, return original
    }

    return decoded;
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

  sanitize(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
}
