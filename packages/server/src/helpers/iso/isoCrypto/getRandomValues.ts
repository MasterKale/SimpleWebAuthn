import { getWebCrypto } from './getWebCrypto.ts';
import type { Uint8Array_ } from '../../../types/index.ts';

/**
 * Fill up the provided bytes array with random bytes equal to its length.
 *
 * @returns the same bytes array passed into the method
 */
export async function getRandomValues(array: Uint8Array_): Promise<Uint8Array_> {
  const WebCrypto = await getWebCrypto();

  WebCrypto.getRandomValues(array);

  return array;
}
