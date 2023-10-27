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
  const _crypto = globalThis.crypto;

  if (_crypto) {
    webCrypto = _crypto;
    return webCrypto;
  }

  try {
    /**
     * `globalThis.crypto` isn't available, so attempt a Node import...
     */
    const _crypto = await _getWebCryptoInternals.stubThisImportNodeCrypto();

    if (_crypto.webcrypto) {
      console.log('node:crypto.webcrypto');
      webCrypto = _crypto.webcrypto as Crypto;
      return webCrypto;
    }
  } catch (_err) {
    // pass
  }

  // We tried to access it both in Node and globally, so bail out
  throw new MissingWebCrypto();
}

class MissingWebCrypto extends Error {
  constructor() {
    const message = 'An instance of the Crypto API could not be located';
    super(message);
    this.name = 'MissingWebCrypto';
  }
}

// Make it possible to stub return values during testing
export const _getWebCryptoInternals = {
  // dnt-shim-ignore
  stubThisImportNodeCrypto: () => import('node:crypto'),
};
