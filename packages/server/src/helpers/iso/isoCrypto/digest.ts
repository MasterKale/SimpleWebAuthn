import type { COSEALG } from '../../cose.ts';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.ts';
import { getWebCrypto } from './getWebCrypto.ts';
import type { Uint8Array_ } from '../../../types/index.ts';

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm A COSE algorithm ID that maps to a desired SHA algorithm
 */
export async function digest(
  data: Uint8Array_,
  algorithm: COSEALG,
): Promise<Uint8Array_> {
  const WebCrypto = await getWebCrypto();

  const subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm);

  const hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);

  return new Uint8Array(hashed);
}
