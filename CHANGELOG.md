# Changelog

All notable changes to Aimless Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
