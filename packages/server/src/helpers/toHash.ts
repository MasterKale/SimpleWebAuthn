import { COSEALG } from './cose.js';
import { isoUint8Array, isoCrypto } from './iso/index.js';

/**
 * Returns hash digest of the given data, using the given algorithm when provided. Defaults to using
 * SHA-256.
 */
export async function toHash(
  data: Uint8Array | string,
  algorithm: COSEALG = -7,
): Promise<Uint8Array> {
  if (typeof data === 'string') {
    data = isoUint8Array.fromUTF8String(data);
  }

  const digest = isoCrypto.digest(data, algorithm);

  return digest;
}
