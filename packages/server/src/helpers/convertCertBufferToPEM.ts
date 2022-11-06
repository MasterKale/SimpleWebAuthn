import type { Base64URLString } from '@simplewebauthn/typescript-types';

import uint8Array from './uint8Array';
import base64url from './base64url';

/**
 * Convert buffer to an OpenSSL-compatible PEM text format.
 */
export function convertCertBufferToPEM(certBuffer: Uint8Array | Base64URLString): string {
  let b64cert: string;

  /**
   * Get certBuffer to a base64 representation
   */
  if (typeof certBuffer === 'string') {
    b64cert = base64url.toBase64(certBuffer);
  } else {
    b64cert = uint8Array.toBase64(certBuffer);
  }

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;

    PEMKey += `${b64cert.substr(start, 64)}\n`;
  }

  PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;

  return PEMKey;
}
