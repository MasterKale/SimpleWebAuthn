import type { Crypto } from '../../../deps.ts';

let webCrypto: Crypto | undefined = undefined;

/**
 * Try to get an instance of the Crypto API from the current runtime. Should support Node,
 * as well as others, like Deno, that implement Web APIs.
 */
export function getWebCrypto(): Crypto {
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

  // We couldn't find WebCrypto so bail out
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
  stubThisGlobalThisCrypto: () => globalThis.crypto,
  // Make it possible to reset the `webCrypto` at the top of the file
  setCachedCrypto: (newCrypto: Crypto | undefined) => {
    webCrypto = newCrypto;
  },
};
