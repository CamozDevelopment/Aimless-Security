/* eslint-disable no-console */
import { LoggingConfig } from './types';

declare const console: any;

export class Logger {
  private config: LoggingConfig;

  constructor(config: LoggingConfig = {}) {
    this.config = {
      enabled: true,
      level: 'info',
      ...config
    };
  }

  private shouldLog(level: string): boolean {
    if (!this.config.enabled) return false;
    
    const levels = ['debug', 'info', 'warn', 'error'];
    const configLevel = levels.indexOf(this.config.level || 'info');
    const messageLevel = levels.indexOf(level);
    
    return messageLevel >= configLevel;
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` | ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] [AIMLESS] [${level.toUpperCase()}] ${message}${metaStr}`;
  }

  debug(message: string, meta?: any): void {
    if (this.shouldLog('debug')) {
      console.debug(this.formatMessage('debug', message, meta));
    }
  }

  info(message: string, meta?: any): void {
    if (this.shouldLog('info')) {
      console.info(this.formatMessage('info', message, meta));
    }
  }

  warn(message: string, meta?: any): void {
    if (this.shouldLog('warn')) {
      console.warn(this.formatMessage('warn', message, meta));
    }
  }

  error(message: string, meta?: any): void {
    if (this.shouldLog('error')) {
      console.error(this.formatMessage('error', message, meta));
    }
  }

  threat(threat: any): void {
    this.warn('Security threat detected', threat);
  }
}
