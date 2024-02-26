import { getWebCrypto } from './getWebCrypto.ts';

/**
 * Fill up the provided bytes array with random bytes equal to its length.
 *
 * @returns the same bytes array passed into the method
 */
export function getRandomValues(array: Uint8Array): Uint8Array {
  const WebCrypto = getWebCrypto();

  WebCrypto.getRandomValues(array);

  return array;
}
