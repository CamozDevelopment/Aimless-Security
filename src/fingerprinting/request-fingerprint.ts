import { RequestFingerprint } from '../types';

export class RequestFingerprintEngine {
  private knownBotPatterns: RegExp[] = [
    /bot|crawler|spider|scraper|curl|wget|postman|insomnia/i,
    /python-requests|go-http-client|java|okhttp/i,
    /headless|phantom|selenium|puppeteer|playwright/i,
    /scanner|nikto|nmap|sqlmap|burp|zap/i
  ];

  private suspiciousHeaders = [
    'x-scanner',
    'x-forwarded-host',
    'x-original-url',
    'x-rewrite-url'
  ];

  analyzeRequest(headers: Record<string, string>): RequestFingerprint {
    const userAgent = headers['user-agent'] || '';
    const acceptLanguage = headers['accept-language'];
    const acceptEncoding = headers['accept-encoding'];
    const connection = headers['connection'];

    // Calculate bot score (0-100)
    let botScore = 0;

    // Check user agent
    if (!userAgent) {
      botScore += 40; // No user agent = very suspicious
    } else {
      for (const pattern of this.knownBotPatterns) {
        if (pattern.test(userAgent)) {
          botScore += 60;
          break;
        }
      }
    }

    // Check for browser characteristics
    if (!acceptLanguage) botScore += 15;
    if (!acceptEncoding) botScore += 15;
    
    // Check for suspicious headers
    for (const header of this.suspiciousHeaders) {
      if (headers[header]) {
        botScore += 10;
      }
    }

    // Check for missing common browser headers
    if (!headers['accept']) botScore += 10;
    if (!headers['accept-language']) botScore += 10;
    
    // Check connection header
    if (connection && connection.toLowerCase() === 'close') {
      botScore += 5; // Bots often close connections
    }

    // Check if user agent matches typical browser pattern
    if (userAgent && !this.looksLikeBrowser(userAgent)) {
      botScore += 20;
    }

    // Generate browser fingerprint (simplified)
    const browserFingerprint = this.generateFingerprint(headers);

    return {
      userAgent,
      acceptLanguage,
      acceptEncoding,
      connection,
      isBot: botScore >= 50,
      botScore: Math.min(100, botScore),
      browserFingerprint
    };
  }

  private looksLikeBrowser(userAgent: string): boolean {
    const browserIndicators = [
      'Mozilla/',
      'Chrome/',
      'Safari/',
      'Firefox/',
      'Edge/',
      'Opera/'
    ];

    return browserIndicators.some(indicator => userAgent.includes(indicator));
  }

  private generateFingerprint(headers: Record<string, string>): string {
    // Simple fingerprint based on header combination
    const components = [
      headers['user-agent'] || '',
      headers['accept-language'] || '',
      headers['accept-encoding'] || '',
      headers['accept'] || ''
    ];

    const fingerprintString = components.join('|');
    
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < fingerprintString.length; i++) {
      const char = fingerprintString.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }

    return Math.abs(hash).toString(36);
  }

  isSuspicious(fingerprint: RequestFingerprint): boolean {
    return fingerprint.isBot || fingerprint.botScore >= 60;
  }

  getRecommendedAction(fingerprint: RequestFingerprint): 'allow' | 'challenge' | 'block' {
    if (fingerprint.botScore >= 80) return 'block';
    if (fingerprint.botScore >= 50) return 'challenge';
    return 'allow';
  }

  generateReport(fingerprint: RequestFingerprint): string {
    const action = this.getRecommendedAction(fingerprint);
    const risk = fingerprint.botScore >= 80 ? 'HIGH' : 
                 fingerprint.botScore >= 50 ? 'MEDIUM' : 'LOW';

    return `
🔍 Request Fingerprint Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bot Score: ${fingerprint.botScore}/100
Risk Level: ${risk}
Is Bot: ${fingerprint.isBot ? 'Yes' : 'No'}
Recommended Action: ${action.toUpperCase()}

User Agent: ${fingerprint.userAgent || 'N/A'}
Accept-Language: ${fingerprint.acceptLanguage || 'N/A'}
Accept-Encoding: ${fingerprint.acceptEncoding || 'N/A'}
Connection: ${fingerprint.connection || 'N/A'}
Fingerprint ID: ${fingerprint.browserFingerprint || 'N/A'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `.trim();
  }
}
