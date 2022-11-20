import type { Base64URLString } from '@simplewebauthn/typescript-types';

import { isoBase64URL } from './iso';

/**
 * Convert buffer to an OpenSSL-compatible PEM text format.
 */
export function convertCertBufferToPEM(certBuffer: Uint8Array | Base64URLString): string {
  let b64cert: string;

  /**
   * Get certBuffer to a base64 representation
   */
  if (typeof certBuffer === 'string') {
    if (isoBase64URL.isBase64url(certBuffer)) {
      b64cert = isoBase64URL.toBase64(certBuffer);
    } else if (isoBase64URL.isBase64(certBuffer)) {
      b64cert = certBuffer;
    } else {
      throw new Error('Certificate is not a valid base64 or base64url string');
    }
  } else {
    b64cert = isoBase64URL.fromBuffer(certBuffer, 'base64');
  }

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;

    PEMKey += `${b64cert.substr(start, 64)}\n`;
  }

  PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;

  return PEMKey;
}
