import crypto from 'crypto';

/**
 * Returns hash digest of the given data using the given algorithm.
 * @param data Data to hash
 * @return The hash
 */
// TODO: Made this async in preparation for trying to use globalThis.crypto (SubtleCrypto) to
// hash values, which returns a Promise
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
export async function toHash(data: Uint8Array | string, algo = 'SHA256'): Promise<Uint8Array> {
  return crypto.createHash(algo).update(data).digest();
}
