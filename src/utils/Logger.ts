import * as core from '@actions/core';

/**
 * Logger utility for consistent logging throughout the application
 */
export class Logger {
  private static instance: Logger;

  constructor() {
    if (Logger.instance) {
      return Logger.instance;
    }
    Logger.instance = this;
  }

  /**
   * Log an info message
   */
  info(message: string): void {
    core.info(message);
    console.log(`[INFO] ${new Date().toISOString()}: ${message}`);
  }

  /**
   * Log a warning message
   */
  warn(message: string): void {
    core.warning(message);
    console.warn(`[WARN] ${new Date().toISOString()}: ${message}`);
  }

  /**
   * Log an error message
   */
  error(message: string): void {
    core.error(message);
    console.error(`[ERROR] ${new Date().toISOString()}: ${message}`);
  }

  /**
   * Log a debug message
   */
  debug(message: string): void {
    core.debug(message);
    console.debug(`[DEBUG] ${new Date().toISOString()}: ${message}`);
  }

  /**
   * Log a notice message
   */
  notice(message: string): void {
    core.notice(message);
    console.log(`[NOTICE] ${new Date().toISOString()}: ${message}`);
  }
}
