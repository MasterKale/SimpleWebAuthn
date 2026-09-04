import type { COSEALG } from '../helpers/cose.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from '../helpers/iso/isoCrypto/mapCoseAlgToWebCryptoKeyAlgName.ts';

export class PQCNotSupportedError extends Error {
  constructor(alg: COSEALG) {
    const webCryptoAlg = mapCoseAlgToWebCryptoKeyAlgName(alg);
    const message = `This runtime's WebCrypto.subtle does not support use of ${webCryptoAlg}`;
    super(message);
    this.name = 'PQCNotSupportedError';
  }
}
