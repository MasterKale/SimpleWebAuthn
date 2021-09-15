import debug, { Debugger } from 'debug';

const defaultLogger = debug('SimpleWebAuthn');

/**
 * Generate an instance of a `debug` logger that extends off of the "simplewebauthn" namespace for
 * consistent naming.
 *
 * See https://www.npmjs.com/package/debug for information on how to control logging output when
 * using @simplewebauthn/server
 *
 * Example:
 *
 * ```
 * const log = getLogger('mds');
 * log('hello'); // simplewebauthn:mds hello +0ms
 * ```
 */
export function getLogger(name: string): Debugger {
  return defaultLogger.extend(name);
}
