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
  };
  // UI Customization
  customBlockMessage?: string; // Custom message after "Request blocked by Aimless Security"
  loadingScreen?: {
    enabled: boolean; // Show "Checking security..." loading screen
    message?: string; // Custom loading message (default: "Checking security...")
    minDuration?: number; // Minimum duration in ms (default: 500)
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
