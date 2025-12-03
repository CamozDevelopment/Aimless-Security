# Changelog

All notable changes to Aimless Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.4] - 2025-12-03

### Added - 🎨 Custom UI & User Experience
- **Custom Loading Screen**: Beautiful dark-themed loading screen with Aimless logo
  - Shows while security checks run
  - Customizable message and duration
  - Smooth animations and professional design
  - Only shows for HTML responses
- **Custom Block Messages**: Define your own message when blocking threats
  - Perfect for support contact info or custom instructions
  - Configurable via `customBlockMessage` in RASP config

### Added - 🔔 Webhook Notifications
- **Discord Webhooks**: Rich embed formatting with color-coded threat levels
- **Slack Webhooks**: Formatted attachment style with threat details
- **Generic Webhooks**: Support for any webhook endpoint
- **Event Filtering**: Choose which events to notify about (block, threat, rateLimit, all)
- **Custom Headers**: Add authentication or custom headers to webhook requests
- **Payload Control**: Option to include/exclude full request payload

### Added - 🤖 Bot Detection & Fingerprinting
- **Request Fingerprinting Engine**: Analyze user-agent and headers for bot patterns
- **Bot Score (0-100)**: Automatic scoring of how likely a request is automated
- **Pattern Detection**: Identifies curl, wget, python-requests, postman, scrapers, headless browsers, security scanners
- **Auto-Block Bots**: Optional automatic blocking of automated traffic
- **Fingerprint Trust**: Option to trust browser fingerprints vs bot patterns

### Added - 📊 Security Analytics Engine
- **Real-Time Metrics**: Track requests, threats, blocks, attack types, and IPs
- **Attack Analytics**: Top attack types and top attacking IPs
- **Retention Control**: Configurable data retention period (default 30 days)
- **Export Capability**: Export raw analytics data for external processing
- **Summary Reports**: Get formatted text summaries of security metrics

### Added - ⚡ Dynamic Rate Limiting
- **IP Reputation-Based**: Adjust rate limits based on IP threat score
- **Suspicious IP Multiplier**: Lower limits for suspicious IPs automatically
- **Adaptive Throttling**: Rate limits that learn from behavior patterns

### Enhanced
- **SQL Injection Detection**: Fixed high-confidence pattern checking (now properly detects `admin'`)
- **Type Definitions**: Enhanced with WebhookPayload, RequestFingerprint, SecurityAnalytics interfaces
- **Demo Server**: Complete v1.3.4 features demo with interactive UI (`examples/v1.3.4-features-demo.js`)
- **Documentation**: Updated docs.html with comprehensive v1.3.4 feature documentation

### API Changes
- **New Methods**:
  - `aimless.getAnalytics()`: Get security analytics data
  - `aimless.getAnalyticsSummary()`: Get formatted analytics summary
  - `aimless.loading()`: Middleware for custom loading screen

### Configuration Changes
```javascript
{
  rasp: {
    // NEW: Custom messages
    customBlockMessage: 'Contact security@example.com',
    
    // NEW: Loading screen
    loadingScreen: {
      enabled: true,
      message: 'Checking security...',
      minDuration: 500
    },
    
    // NEW: Webhooks
    webhooks: {
      enabled: true,
      url: 'https://discord.com/api/webhooks/...',
      events: ['block', 'threat'],
      includePayload: false,
      customHeaders: {}
    },
    
    // NEW: Bot detection
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: true,
      trustBrowserFingerprints: true
    },
    
    // NEW: Analytics
    analytics: {
      enabled: true,
      retention: 30
    },
    
    // ENHANCED: Rate limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000,
      dynamicThrottling: true,        // NEW
      suspiciousIPMultiplier: 0.5     // NEW
    }
  }
}
```

### Fixed
- **SQL Injection**: High-confidence patterns (like `admin'`) now properly detected independently
- **Webhooks**: Discord/Slack formatting now works correctly (no more 400 errors)
- **Middleware Flow**: Loading screen properly shows before security checks

## [1.3.1] - 2025-11-20

### Added
- **Enhanced Detection Patterns**: 50+ new patterns across all threat types
  - **SQL Injection**: Added admin bypass, multi-line comments, database fingerprinting, NULL byte injection
  - **NoSQL Injection**: Added prototype pollution, server-side JS, MongoDB $function operator
  - **Command Injection**: Added package managers, reverse shells, compression attacks, base64 decoding
  - **Path Traversal**: Better detection with UNC paths and multiple slash patterns
- **False Positive Prevention**: Significantly reduced false positives
  - Requires 2+ pattern matches for most threats (unless high-confidence pattern)
  - Context-aware whitelisting (email, username, name, uuid, date, url, number)
  - Smart value detection (prose, safe words, normal text)
  - Input length filtering (skip < 2 chars or > 10000 chars)
- **Improved Confidence Scoring**: More realistic confidence levels
  - 1 match = 30%, 2 matches = 60%, 3 matches = 85%, 4+ matches = 90-100%
- **Comprehensive Testing**: 23/23 false positive prevention tests passing

### Fixed
- Package name changed from `aimless-security` to `aimless-sdk`
- Validate API now correctly detects XSS threats
- Type map in validate() updated to match actual threat type values

## [1.3.0] - 2025-11-19

### Added
- **🎯 ENDPOINT ACCESS CONTROL**: Define exactly which APIs are allowed to execute
  - **Allowlist Mode**: Only specified endpoints can be accessed (strict whitelist)
  - **Blocklist Mode**: Block specific dangerous endpoints while allowing everything else
  - **Protected Endpoints**: Apply extra security rules to sensitive routes (payments, admin, etc.)
  - **Regex & Wildcard Support**: Flexible endpoint matching with `/api/*` and regex patterns
  - **Per-Endpoint Rules**: Custom security levels, authentication requirements, rate limits
  - **Method Filtering**: Allow only specific HTTP methods per endpoint
  - **Auth Requirements**: Require authentication headers for protected endpoints
  - **Threat Level Limits**: Set maximum allowed threat level per endpoint (low/medium/high/critical)
- **New Example**: `examples/access-control.js` with 6 comprehensive configuration examples
- **Access Control Types**: `EndpointRule`, `AccessControlConfig` interfaces

### Changed
- **Middleware**: Now checks access control before running threat analysis
- **Protection Flow**: 3-step process: Access Control → Threat Analysis → Protected Endpoint Rules
- **RASP Config**: Added `accessControl` configuration object

### Security
- Protected endpoints can override global security settings
- Authentication headers are checked before request processing
- Unmatched endpoints can be configured to allow or block by default

## [1.2.0] - 2025-11-19

### Fixed
- **CRITICAL**: Default `blockMode` changed to `false` (detection-only mode)
- Package no longer blocks legitimate traffic by default
- Disabled aggressive features: CSRF protection, anomaly detection, rate limiting by default

### Changed
- **Safe Defaults**: Users must explicitly enable blocking and aggressive features
- Detection-only mode allows monitoring before enforcement

## [1.1.2] - 2025-11-19

### Fixed
- **Vercel Compatibility**: Fixed module resolution issues on Vercel and serverless platforms
- **Package Exports**: Added proper `exports` field for better CommonJS/ESM interoperability
- **Dependencies**: Moved Express to peer dependencies (optional) to reduce bundle size
- **Module Loading**: Improved compatibility with Next.js and other bundlers

### Added
- **VERCEL.md**: Comprehensive deployment guide for Vercel and serverless platforms
- **.npmignore**: Ensures only necessary files are published to NPM
- **sideEffects**: false flag for better tree-shaking

### Changed
- **Version**: Bumped to 1.1.2 for serverless compatibility release
- **TypeScript Config**: Added `allowSyntheticDefaultImports` and `isolatedModules` for better compatibility

## [1.1.1] - 2025-11-19

### Fixed
- Minor bug fixes and improvements
- Documentation updates

## [1.1.0] - 2025-11-19

### Enhanced Detection Capabilities
- **SQL Injection Detection**: Added 20+ new patterns including time-based blind injection, error-based injection, and information schema access detection
- **XSS Protection**: Implemented multi-layer decoding, mutation XSS (mXSS) detection, DOM-based XSS patterns, and context-aware sanitization (HTML, JavaScript, CSS, URL)
- **NoSQL Injection**: Expanded detection to cover MongoDB aggregation, CouchDB, Redis, and Cassandra CQL injections
- **Command Injection**: Added PowerShell-specific patterns, file redirection detection, and environment variable manipulation checks
- **Path Traversal**: Enhanced with double encoding detection, Unicode variations, UNC paths, and overlong UTF-8 sequences
- **XXE Detection**: Added parameter entities, external DTD, XSLT attacks, and XML processing instruction detection
- **SSRF Protection**: Expanded to detect cloud metadata endpoints (AWS, Google Cloud, Azure), DNS rebinding, and multiple localhost representations

### Advanced Security Features
- **Confidence Scoring**: All detections now include confidence percentages based on pattern match counts
- **IP Reputation System**: Track IP behavior with automatic reputation scoring, violation counting, and auto-blocking
- **Behavioral Analysis**: Machine learning-like anomaly detection with request velocity analysis and fingerprinting
- **CSRF Enhancements**: 
  - Timing-safe token comparison to prevent timing attacks
  - One-time token support
  - Double-submit cookie validation
  - Automatic token cleanup to prevent memory leaks
  - Token expiration management with customizable timeouts

### Fuzzing Engine Improvements
- **Response Analysis**: Smart response evaluation with error detection and vulnerability scoring
- **Severity Calculation**: Dynamic severity assignment based on vulnerability scores (0-100)
- **Enhanced Payload Detection**: Better categorization of SQL, XSS, NoSQL, Path Traversal, and Command Injection payloads

### Developer Experience
- **Fluent API**: New validation chain for elegant input validation
  ```typescript
  aimless.validate(userInput).against(['sql', 'xss']).sanitize().result()
  ```
- **Quick Start Helper**: One-line protection setup with `Aimless.quickProtect()`
- **Context-Aware Sanitization**: `sanitizeFor(input, 'html'|'javascript'|'css'|'url'|'attribute')`
- **Validation Helpers**:
  - `isSafe(input)` - Quick safety check
  - `validateAndSanitize(input)` - Combined validation and sanitization
  - `getIPReputation(ip)` - Get IP reputation score (0-100)
  - `setIPBlocked(ip, blocked)` - Manual IP blocking
  - `getStats()` - Security statistics and monitoring
  - `clearHistory(ip?)` - History management for privacy/testing

### Performance & Reliability
- **Whitelist Support**: Reduce false positives with context-aware whitelisting
- **Memory Management**: Automatic cleanup of expired tokens and old request history
- **Request History Limits**: Configurable history size to prevent memory exhaustion

### Documentation
- Comprehensive inline documentation with JSDoc comments
- Type definitions for all new methods and interfaces
- Migration guide for upgrading from 1.0.x

### Breaking Changes
None - fully backward compatible with v1.0.x

## [1.0.0] - 2025-11-19

### Added
- Initial release of Aimless Security
- Runtime Application Self-Protection (RASP) features:
  - SQL injection detection
  - NoSQL injection detection
  - Command injection detection
  - XSS (Cross-Site Scripting) protection
  - CSRF (Cross-Site Request Forgery) protection
  - Path traversal detection
  - XXE (XML External Entity) detection
  - SSRF (Server-Side Request Forgery) detection
  - Anomaly detection and rate limiting
  - Real-time threat blocking
- API Fuzzing Engine features:
  - Smart parameter mutation
  - Authentication bypass testing
  - Rate limit testing
  - GraphQL introspection
  - Comprehensive payload generation
- Express middleware integration
- TypeScript support with full type definitions
- Configurable logging system
- CSRF token generation and validation
- XSS output sanitization
- Comprehensive documentation and examples

### Security
- All security patterns based on OWASP Top 10
- Pattern matching optimized for performance
- No external dependencies for core security features

## [Unreleased]

### Planned
- Fastify middleware support
- Koa middleware support
- Advanced machine learning-based anomaly detection
- Custom rule engine
- WebSocket protection
- API rate limiting with Redis backend
- Security report generation
- Integration with SIEM systems
- Browser SDK for client-side protection
