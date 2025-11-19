export interface AimlessConfig {
  rasp?: RASPConfig;
  fuzzing?: FuzzingConfig;
  logging?: LoggingConfig;
}

export interface RASPConfig {
  enabled?: boolean;
  injectionProtection?: boolean;
  xssProtection?: boolean;
  csrfProtection?: boolean;
  anomalyDetection?: boolean;
  blockMode?: boolean; // true = block, false = monitor only
  trustedOrigins?: string[];
  maxRequestSize?: number; // bytes
  rateLimiting?: {
    enabled: boolean;
    maxRequests: number;
    windowMs: number;
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
