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
  // @ts-ignore: ...right here.
  let _crypto: Crypto = globalThis.crypto;

  try {
    /**
     * Naively attempt a Node import...
     */
    // @ts-ignore: We'll handle any errors...
    // dnt-shim-ignore
    const nodeCrypto = await import('node:crypto');
    if (nodeCrypto.webcrypto) {
      _crypto = nodeCrypto.webcrypto as Crypto;
    }
  } catch {}

  if (!_crypto) {
    // We tried to access it both in Node and globally, so bail out
    throw new MissingWebCrypto();
  }
  
  webCrypto = _crypto;

  return webCrypto;
}

class MissingWebCrypto extends Error {
  constructor() {
    const message = 'An instance of the Crypto API could not be located';
    super(message);
    this.name = 'MissingWebCrypto';
  }
}
