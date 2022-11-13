import { webcrypto } from 'node:crypto';

import { isoUint8Array } from './iso';

/**
 * Returns hash digest of the given data using the given algorithm.
 * @param data Data to hash
 * @return The hash
 */
export async function toHash(data: Uint8Array | string, algorithm = 'SHA-256'): Promise<Uint8Array> {
  if (/sha\d{1,3}/i.test(algorithm)) {
    // Convert algorithms like "SHA1", "SHA256", etc... into values like "SHA-1", "SHA-256", etc...
    // that `.digest()` will accept
    algorithm = algorithm.toUpperCase().replace('SHA', 'SHA-');
  }

  if (typeof data === 'string') {
    data = isoUint8Array.fromUTF8String(data);
  }

  let hashed: ArrayBuffer
  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    hashed = await globalThis.crypto.subtle.digest(algorithm, data);
  } else {
    // We're in Node, use Node's Crypto
    hashed = await webcrypto.subtle.digest(algorithm, data);
  }

  return new Uint8Array(hashed);
}
