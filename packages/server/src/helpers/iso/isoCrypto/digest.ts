import { webcrypto } from 'node:crypto';

import { COSEALG } from '../../cose';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg';

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm A COSE algorithm ID that maps to the SHA algorithm. Default: `-7` (for SHA-256)
 */
 export async function digest(data: Uint8Array, algorithm: COSEALG): Promise<Uint8Array> {
  const subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm);

  let hashed: ArrayBuffer
  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    hashed = await globalThis.crypto.subtle.digest(subtleAlgorithm, data);
  } else {
    // We're in Node, use Node's Crypto
    hashed = await webcrypto.subtle.digest(subtleAlgorithm, data);
  }

  return new Uint8Array(hashed);
}
