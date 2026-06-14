/**
 * A basic logging interface that enables projects to capture logging output from SimpleWebAuthn
 * using whatever logging method is appropriate for the project. Logging levels can be defined
 * independently to only capture desired levels.
 *
 * For example, a project using `console` statements to capture logs can use the following
 * implementation of this interface:
 *
 * ```ts
 * const ConsoleLogger: SimpleWebAuthnLogger = {
 *   // debug(message: string, ...args: unknown[]) { console.debug(message, ...args); },
 *   info(message: string, ...args: unknown[]) { console.info(message, ...args); },
 *   warn(message: string, ...args: unknown[]) { console.warn(message, ...args); },
 *   error(message: string, ...args: unknown[]) { console.error(message, ...args); },
 * };
 * ```
 */
export interface SimpleWebAuthnLogger {
  debug?: (message: string, ...args: unknown[]) => void;
  info?: (message: string, ...args: unknown[]) => void;
  warn?: (message: string, ...args: unknown[]) => void;
  error?: (message: string, ...args: unknown[]) => void;
}

/**
 * A logger instance that doesn't do anything. Useful as a default argument when no custom instance
 * of the `SimpleWebAuthnLogger` interface is specified.
 */
export const DefaultNoopLogger: Required<SimpleWebAuthnLogger> = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/**
 * Generate an instance of SimpleWebAuthnLogger that defines all methods. Any logging method not
 * defined on `logger` will be a no-op.
 */
export function buildLoggerAllMethods(
  logger: SimpleWebAuthnLogger,
): Required<SimpleWebAuthnLogger> {
  const toReturn: Required<SimpleWebAuthnLogger> = { ...DefaultNoopLogger };

  if (logger.debug) {
    toReturn.debug = logger.debug;
  }

  if (logger.info) {
    toReturn.info = logger.info;
  }

  if (logger.warn) {
    toReturn.warn = logger.warn;
  }

  if (logger.error) {
    toReturn.error = logger.error;
  }

  return toReturn;
}
