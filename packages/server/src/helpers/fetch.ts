/**
 * A simple method for requesting data via standard `fetch`. Should work
 * across multiple runtimes.
 */
export function fetch(...args: Parameters<typeof globalThis.fetch>): Promise<Response> {
  return _fetchInternals.stubThis(...args);
}

/**
 * Make it possible to stub the return value during testing
 * @ignore Don't include this in docs output
 */
export const _fetchInternals = {
  stubThis: (...args: Parameters<typeof globalThis.fetch>) => globalThis.fetch(...args),
};
