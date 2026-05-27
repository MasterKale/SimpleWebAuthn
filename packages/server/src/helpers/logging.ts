/**
 * A basic logging interface that enables projects to capture logging output from SimpleWebAuthn
 * using whatever logging method is appropriate for the project.
 *
 * For example, a project using `console` statements to capture logs can use the following
 * implementation of this interface:
 *
 * ```ts
 * const ConsoleLogger: SimpleWebAuthnLogger = {
 *   debug(message: string, ...args: unknown[]) { console.debug(message, ...args); },
 *   info(message: string, ...args: unknown[]) { console.info(message, ...args); },
 *   warn(message: string, ...args: unknown[]) { console.warn(message, ...args); },
 *   error(message: string, ...args: unknown[]) { console.error(message, ...args); },
 * };
 * ```
 */
export interface SimpleWebAuthnLogger {
  debug: (message: string, ...args: unknown[]) => void;
  info: (message: string, ...args: unknown[]) => void;
  warn: (message: string, ...args: unknown[]) => void;
  error: (message: string, ...args: unknown[]) => void;
}
