import { webcrypto } from 'node:crypto';

/**
 * Fill up the provided bytes array with random bytes equal to its length.
 *
 * @returns the same bytes array passed into the method
 */
export function getRandomValues(array: Uint8Array): Uint8Array {
  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    globalThis.crypto.getRandomValues(array);
  } else {
    // We're in Node, use Node's Crypto
    webcrypto.getRandomValues(array);
  }

  return array;
}

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
  algorithm = normalizeAlgorithm(algorithm);

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

/**
 * Convert algorithms like "SHA1", "sha256", etc... into values like "SHA-1", "SHA-256", etc...
 * that `.digest()` will accept
 */
function normalizeAlgorithm(algorithm: string): string {
  if (/sha\d{1,3}/i.test(algorithm)) {
    algorithm = algorithm.toUpperCase().replace('SHA', 'SHA-');
  }

  return algorithm;
/**
 * Convert a COSE crv ID into a corresponding string value that WebCrypto APIs expect
 */
function mapCoseCrvToWebCryptoCrv(crv: number): SubtleCryptoCrv {
  if (crv === 1) {
    return 'P-256';
  }

  if (crv === 2) {
    return 'P-384';
  }

  if (crv === 3) {
    return 'P-521';
  }

  throw new Error(`Unexpected COSE crv value of ${crv}`);
}
type SubtleCryptoCrv = "P-256" | "P-384" | "P-521";

/**
 * Convert a COSE alg ID into a corresponding string value that WebCrypto APIs expect
 */
function mapCoseAlgToWebCryptoAlg(alg: number): SubtleCryptoAlg {
  if ([-65535].indexOf(alg) >= 0) {
    return 'SHA-1';
  } else if ([-7, -37, -257].indexOf(alg) >= 0) {
    return 'SHA-256';
  } else if ([-35, -38, -258].indexOf(alg) >= 0) {
    return 'SHA-384'
  } else if ([-8, -36, -39, -259].indexOf(alg) >= 0) {
    return 'SHA-512';
  }

  throw new Error(`Unexpected COSE alg value of ${alg}`);
}
export type SubtleCryptoAlg = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
