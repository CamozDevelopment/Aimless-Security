/**
 * Safety Wrapper for Aimless Security
 * 
 * This wrapper adds extra error handling and graceful degradation
 * for production environments. Use this in serverless/edge environments
 * where you want guaranteed availability even if the security layer fails.
 */

const { Aimless } = require('aimless-sdk');

class SafeAimless {
  constructor(config = {}) {
    try {
      this.aimless = new Aimless(config);
      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize Aimless Security:', error);
      this.initialized = false;
      this.aimless = null;
    }
  }

  /**
   * Safe validation - never throws, always returns boolean
   */
  isSafe(input) {
    if (!this.initialized || !this.aimless) {
      console.warn('Aimless not initialized, allowing input (fail-open)');
      return true; // Fail open - allow traffic if security is down
    }

    try {
      return this.aimless.isSafe(input);
    } catch (error) {
      console.error('Validation error:', error);
      return true; // Fail open on error
    }
  }

  /**
   * Safe sanitization - returns original input if sanitization fails
   */
  sanitizeFor(input, context) {
    if (!this.initialized || !this.aimless) {
      return input; // Return original if security is down
    }

    try {
      return this.aimless.sanitizeFor(input, context);
    } catch (error) {
      console.error('Sanitization error:', error);
      return input; // Return original on error
    }
  }

  /**
   * Express middleware with error handling
   */
  middleware() {
    if (!this.initialized || !this.aimless) {
      // Return pass-through middleware if not initialized
      return (req, res, next) => {
        console.warn('Aimless middleware not active');
        next();
      };
    }

    const actualMiddleware = this.aimless.middleware();

    // Wrap middleware with try-catch
    return (req, res, next) => {
      try {
        actualMiddleware(req, res, next);
      } catch (error) {
        console.error('Middleware error:', error);
        next(); // Continue request even if middleware fails
      }
    };
  }

  /**
   * Safe IP reputation check
   */
  getIPReputation(ip) {
    if (!this.initialized || !this.aimless) {
      return 100; // Default to good reputation
    }

    try {
      return this.aimless.getIPReputation(ip);
    } catch (error) {
      console.error('IP reputation error:', error);
      return 100;
    }
  }

  /**
   * Check if security layer is working
   */
  isHealthy() {
    if (!this.initialized) return false;
    
    try {
      // Quick smoke test
      const testResult = this.aimless.isSafe('test');
      return typeof testResult === 'boolean';
    } catch {
      return false;
    }
  }

  /**
   * Get statistics (safe)
   */
  getStats() {
    if (!this.initialized || !this.aimless) {
      return { error: 'Not initialized' };
    }

    try {
      return this.aimless.getStats();
    } catch (error) {
      return { error: error.message };
    }
  }
}

/**
 * Quick setup function with safety wrapper
 */
function createSafeAimless(config = {}) {
  // Default to fail-open mode for serverless
  const safeConfig = {
    rasp: {
      enabled: true,
      blockMode: false, // Detection only by default
      ...config.rasp
    },
    logging: {
      enabled: true,
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info',
      ...config.logging
    },
    ...config
  };

  return new SafeAimless(safeConfig);
}

module.exports = { SafeAimless, createSafeAimless };

// Example usage:
// const { createSafeAimless } = require('./safe-aimless');
// const aimless = createSafeAimless({
//   rasp: {
//     trustedOrigins: ['https://yourdomain.com']
//   }
// });
// 
// app.use(aimless.middleware());
// 
// app.post('/api/contact', (req, res) => {
//   if (!aimless.isSafe(req.body.message)) {
//     return res.status(400).json({ error: 'Invalid input' });
//   }
//   // Process request...
// });
