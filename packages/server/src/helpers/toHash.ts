import crypto from 'crypto';

/**
 * Returns hash digest of the given data using the given algorithm.
 * @param data Data to hash
 * @return The hash
 */
export default function toHash(data: Buffer | string, algo = 'SHA256'): Buffer {
  return crypto.createHash(algo).update(data).digest();
}
