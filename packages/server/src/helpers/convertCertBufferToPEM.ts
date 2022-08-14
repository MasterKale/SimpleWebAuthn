import base64url from 'base64url';
import type { Base64URLString } from '@simplewebauthn/typescript-types';

/**
 * Convert buffer to an OpenSSL-compatible PEM text format.
 */
export function convertCertBufferToPEM(certBuffer: Buffer | Base64URLString): string {
  let b64cert: string;

  /**
   * Get certBuffer to a base64 representation
   */
  if (typeof certBuffer === 'string') {
    b64cert = base64url.toBase64(certBuffer);
  } else {
    b64cert = certBuffer.toString('base64');
  }

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;

    PEMKey += `${b64cert.substr(start, 64)}\n`;
  }

  PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;

  return PEMKey;
}
