/**
 * A simple method for requesting data via standard `fetch`. Should work
 * across multiple runtimes.
 */
export function fetch(url: string): Promise<Response> {
  return _fetchInternals.stubThis(url);
}

/**
 * Make it possible to stub the return value during testing
 * @ignore Don't include this in docs output
 */
export const _fetchInternals = {
  stubThis: (url: string) => globalThis.fetch(url),
};
