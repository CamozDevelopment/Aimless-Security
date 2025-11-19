# Changelog

All notable changes to Aimless Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
