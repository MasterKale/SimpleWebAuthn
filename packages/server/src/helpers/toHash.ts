import crypto from 'crypto';

/**
 * Returns hash digest of the given data using the given algorithm.
 * @param data Data to hash
 * @return The hash
 */
export function toHash(data: Uint8Array | string, algo = 'SHA256'): Uint8Array {
  return crypto.createHash(algo).update(data).digest();
}
