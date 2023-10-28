import type { Crypto } from '../../../deps.ts';

let webCrypto: Crypto | undefined = undefined;

/**
 * Try to get an instance of the Crypto API from the current runtime. Should support Node,
 * as well as others, like Deno, that implement Web APIs.
 */
export async function getWebCrypto(): Promise<Crypto> {
  if (webCrypto) {
    return webCrypto;
  }

  /**
   * Naively attempt to access Crypto as a global object, which popular alternative run-times
   * support.
   */
  const _globalThisCrypto = _getWebCryptoInternals.stubThisGlobalThisCrypto();

  if (_globalThisCrypto) {
    webCrypto = _globalThisCrypto;
    return webCrypto;
  }

  /**
   * `globalThis.crypto` isn't available, so attempt a Node import...
   */
  const _nodeCrypto = await _getWebCryptoInternals.stubThisImportNodeCrypto();

  if (_nodeCrypto?.webcrypto) {
    webCrypto = _nodeCrypto.webcrypto as Crypto;
    return webCrypto;
  }

  // We tried to access it both in Node and globally, so bail out
  throw new MissingWebCrypto();
}

export class MissingWebCrypto extends Error {
  constructor() {
    const message = 'An instance of the Crypto API could not be located';
    super(message);
    this.name = 'MissingWebCrypto';
  }
}

// Make it possible to stub return values during testing
export const _getWebCryptoInternals = {
  stubThisImportNodeCrypto: async () => {
    try {
      // dnt-shim-ignore
      const _nodeCrypto = await import('node:crypto');
      return _nodeCrypto;
    } catch (_err) {
      /**
       * Intentionally declaring webcrypto as undefined because we're assuming the Node import
       * failed due to either:
       * - `import()` isn't supported
       * - `node:crypto` is unavailable.
       */
      return { webcrypto: undefined };
    }
  },
  stubThisGlobalThisCrypto: () => globalThis.crypto,
  // Make it possible to reset the `webCrypto` at the top of the file
  setCachedCrypto: (newCrypto: Crypto | undefined) => {
    webCrypto = newCrypto;
  },
};
