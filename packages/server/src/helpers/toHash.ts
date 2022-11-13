import { isoUint8Array, isoCrypto } from './iso';

/**
 * Returns hash digest of the given data, using the given algorithm when provided
 */
export async function toHash(data: Uint8Array | string, algorithm = 'SHA-256'): Promise<Uint8Array> {
  if (typeof data === 'string') {
    data = isoUint8Array.fromUTF8String(data);
  }

  const digest = isoCrypto.digest(data, algorithm);

  return digest;
}
