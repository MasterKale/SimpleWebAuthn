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

  try {
    /**
     * Naively attempt a Node import...
     */
    // @ts-ignore: We'll handle any errors...
    // dnt-shim-ignore
    const _crypto = await require('node:crypto');
    webCrypto = _crypto as unknown as Crypto;
  } catch (_err) {
    /**
     * Naively attempt to access Crypto as a global object, which popular alternative run-times
     * support.
     */
    // @ts-ignore: ...right here.
    const _crypto: Crypto = globalThis.crypto;

    if (!_crypto) {
      // We tried to access it both in Node and
      throw new MissingWebCrypto();
    }

    webCrypto = _crypto;
  }

  return webCrypto;
}

class MissingWebCrypto extends Error {
  constructor() {
    const message = 'An instance of the Crypto API could not be located';
    super(message);
    this.name = 'MissingWebCrypto';
  }
}
