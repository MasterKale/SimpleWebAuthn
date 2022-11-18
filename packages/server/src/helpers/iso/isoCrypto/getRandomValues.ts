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
