import type { Crypto } from './deps.ts';

/** */
async function getCrypto(): Promise<Crypto> {
  try {
    /**
     * Start by trying to import crypto from Node.
     */
    // @ts-ignore 2580
    const crypto = await require('node:crypto');
    console.log('Probably Node');
    return crypto.webcrypto as unknown as Crypto;
  } catch (_err) {
    /**
     * We're probably in a browser-like environment, `crypto` should be available globally whether
     * in the DOM, in a service worker, etc...
     */
    const crypto: Crypto = globalThis.crypto;
    console.log('Probably Browser, CF Worker, etc...');
    return crypto;
  }
}

const WebCrypto = await getCrypto();

export default WebCrypto;
