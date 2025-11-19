# Aimless Security - Contributing Guide

Thank you for your interest in contributing to Aimless Security!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/aimless-security.git`
3. Install dependencies: `npm install`
4. Create a branch: `git checkout -b feature/your-feature-name`

## Development

### Building

```bash
npm run build
```

### Running Tests

```bash
npm test
```

### Linting

```bash
npm run lint
```

## Project Structure

```
aimless-security/
├── src/
│   ├── rasp/              # RASP protection modules
│   │   ├── injection-detector.ts
│   │   ├── xss-detector.ts
│   │   ├── csrf-detector.ts
│   │   ├── anomaly-detector.ts
│   │   └── index.ts
│   ├── fuzzing/           # API fuzzing engine
│   │   ├── payload-generator.ts
│   │   └── index.ts
│   ├── middleware/        # Framework integrations
│   │   └── express.ts
│   ├── types.ts           # TypeScript definitions
│   ├── logger.ts          # Logging utility
│   └── index.ts           # Main export
├── examples/              # Usage examples
├── dist/                  # Compiled output
└── package.json
```

## Adding New Features

### Adding a New Threat Detector

1. Create a new detector in `src/rasp/`
2. Add threat type to `ThreatType` enum in `src/types.ts`
3. Integrate into `src/rasp/index.ts`
4. Add tests
5. Update README.md

### Adding New Fuzzing Payloads

1. Update `src/fuzzing/payload-generator.ts`
2. Add payload arrays for new attack types
3. Update `getAll()` and `mutateValue()` methods
4. Add tests

### Adding Framework Support

1. Create new middleware in `src/middleware/`
2. Follow the Express middleware pattern
3. Export from `src/index.ts`
4. Add example in `examples/`
5. Document in README.md

## Code Style

- Use TypeScript for all new code
- Follow existing code patterns
- Use meaningful variable names
- Add JSDoc comments for public APIs
- Keep functions focused and small

## Testing

- Write tests for all new features
- Maintain test coverage above 80%
- Test both success and failure cases
- Include edge cases

## Pull Request Process

1. Update README.md with details of changes
2. Update examples if needed
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review from maintainers

## Security

If you discover a security vulnerability, please email security@aimless.dev instead of using the issue tracker.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
