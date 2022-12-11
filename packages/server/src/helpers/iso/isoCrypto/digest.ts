import WebCrypto from '@simplewebauthn/iso-webcrypto';

import { COSEALG } from '../../cose';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg';

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm A COSE algorithm ID that maps to a desired SHA algorithm
 */
export async function digest(data: Uint8Array, algorithm: COSEALG): Promise<Uint8Array> {
  const subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm);

  const hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);

  return new Uint8Array(hashed);
}
