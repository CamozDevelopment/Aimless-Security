export interface AimlessConfig {
  rasp?: RASPConfig;
  fuzzing?: FuzzingConfig;
  logging?: LoggingConfig;
}

export interface EndpointRule {
  path: string | RegExp; // Exact path or regex pattern
  methods?: string[]; // Allowed methods (GET, POST, etc.). If omitted, all methods allowed
  requireAuth?: boolean; // Require authentication header
  maxThreatLevel?: 'low' | 'medium' | 'high' | 'critical'; // Max allowed threat level
  rateLimit?: { // Override global rate limit for this endpoint
    maxRequests: number;
    windowMs: number;
  };
}

export interface AccessControlConfig {
  mode: 'allowlist' | 'blocklist' | 'monitor'; // Access control mode
  allowedEndpoints?: EndpointRule[]; // Whitelist of allowed endpoints
  protectedEndpoints?: EndpointRule[]; // Extra security for sensitive endpoints
  blockedEndpoints?: (string | RegExp)[]; // Explicitly blocked endpoints
  defaultAction?: 'allow' | 'block'; // What to do with unmatched endpoints
  requireAuthHeader?: string; // e.g., 'Authorization' or 'X-API-Key'
}

export interface RASPConfig {
  enabled?: boolean;
  injectionProtection?: boolean;
  xssProtection?: boolean;
  csrfProtection?: boolean;
  anomalyDetection?: boolean;
  blockMode?: boolean; // true = block threats, false = monitor only
  accessControl?: AccessControlConfig; // NEW: Endpoint access control
  trustedOrigins?: string[];
  maxRequestSize?: number; // bytes
  rateLimiting?: {
    enabled: boolean;
    maxRequests: number;
    windowMs: number;
    dynamicThrottling?: boolean; // Adjust limits based on IP reputation
    suspiciousIPMultiplier?: number; // Rate limit multiplier for suspicious IPs (default: 0.5)
  };
  // UI Customization
  customBlockMessage?: string; // Custom message after "Request blocked by Aimless Security"
  loadingScreen?: {
    enabled: boolean; // Show "Checking security..." loading screen
    message?: string; // Custom loading message (default: "Checking security...")
    minDuration?: number; // Minimum duration in ms (default: 500)
  };
  // Advanced Features
  webhooks?: {
    enabled: boolean;
    url: string; // Webhook URL for attack notifications
    events?: ('block' | 'threat' | 'rateLimit' | 'all')[]; // Which events to send
    includePayload?: boolean; // Include attack payload in webhook (default: false)
    customHeaders?: Record<string, string>; // Custom headers for webhook
  };
  requestFingerprinting?: {
    enabled: boolean; // Enable browser/bot fingerprinting
    blockAutomatedTraffic?: boolean; // Auto-block obvious bots
    trustBrowserFingerprints?: boolean; // Allow known good fingerprints
  };
  analytics?: {
    enabled: boolean; // Enable detailed analytics
    retention?: number; // Days to keep analytics data (default: 30)
  };
}

export interface FuzzingConfig {
  enabled?: boolean;
  maxPayloads?: number;
  timeout?: number; // ms
  authBypassTests?: boolean;
  rateLimitTests?: boolean;
  graphqlIntrospection?: boolean;
  customPayloads?: string[];
}

export interface LoggingConfig {
  enabled?: boolean;
  level?: 'debug' | 'info' | 'warn' | 'error';
  logFile?: string;
}

export interface SecurityThreat {
  type: ThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  payload?: string;
  timestamp: Date;
  blocked: boolean;
  confidence?: number; // 0-100 confidence score
  metadata?: Record<string, any>;
}

export enum ThreatType {
  SQL_INJECTION = 'sql_injection',
  NOSQL_INJECTION = 'nosql_injection',
  COMMAND_INJECTION = 'command_injection',
  XSS = 'xss',
  CSRF = 'csrf',
  PATH_TRAVERSAL = 'path_traversal',
  XXE = 'xxe',
  SSRF = 'ssrf',
  ANOMALOUS_BEHAVIOR = 'anomalous_behavior',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  AUTH_BYPASS_ATTEMPT = 'auth_bypass_attempt'
}

export interface FuzzingResult {
  endpoint: string;
  method: string;
  vulnerabilities: SecurityThreat[];
  testedPayloads: number;
  duration: number;
  timestamp: Date;
}

export interface WebhookPayload {
  event: 'block' | 'threat' | 'rateLimit';
  timestamp: Date;
  ip: string;
  path: string;
  method: string;
  threats?: SecurityThreat[];
  payload?: any;
  userAgent?: string;
  reputation?: number;
}

export interface RequestFingerprint {
  userAgent: string;
  acceptLanguage?: string;
  acceptEncoding?: string;
  connection?: string;
  isBot: boolean;
  botScore: number; // 0-100, higher = more likely bot
  browserFingerprint?: string;
}

export interface SecurityAnalytics {
  totalRequests: number;
  threatsDetected: number;
  threatsBlocked: number;
  topAttackTypes: Array<{ type: string; count: number }>;
  topAttackIPs: Array<{ ip: string; count: number; reputation: number }>;
  requestsByHour: Array<{ hour: number; count: number; threats: number }>;
  geographicData?: Array<{ country: string; requests: number; threats: number }>;
  averageResponseTime: number;
  uptime: number;
}
