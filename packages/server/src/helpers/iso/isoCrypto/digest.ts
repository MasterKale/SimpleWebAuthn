import { webcrypto } from 'node:crypto';

import { normalizeSHAAlgorithm } from './normalizeSHAAlgorithm';

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm Must be one of the following values:
 * - `"SHA-1"`
 * - `"SHA-256"`
 * - `"SHA-384"`
 * - `"SHA-512"`
 */
 export async function digest(data: Uint8Array, algorithm: string): Promise<Uint8Array> {
  algorithm = normalizeSHAAlgorithm(algorithm);

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
