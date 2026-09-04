import type { COSEALG } from '../helpers/cose.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from '../helpers/iso/isoCrypto/mapCoseAlgToWebCryptoKeyAlgName.ts';

/**
 * Base error class that helps disambiguate SimpleWebAuthn library errors from other library errors
 */
export class SimpleWebAuthnError extends Error {
  code: SimpleWebAuthnErrorCode;

  constructor({ message, code, cause }: {
    message: string;
    code: SimpleWebAuthnErrorCode;
    cause?: Error;
  }) {
    super(message, { cause });
    this.name = 'SimpleWebAuthnError';
    this.code = code;
  }
}

export class PQCNotSupportedError extends SimpleWebAuthnError {
  constructor(alg: COSEALG) {
    const webCryptoAlg = mapCoseAlgToWebCryptoKeyAlgName(alg);
    const message = `This runtime's WebCrypto.subtle does not support use of ${webCryptoAlg}`;
    super({ message, code: 'RUNTIME_NO_PQC_SUPPORT' });
  }
}

export type SimpleWebAuthnErrorCode = 'RUNTIME_NO_PQC_SUPPORT';
