import { isoBase64URL } from './iso';

/**
 * Take a certificate in PEM format and convert it to bytes
 */
export function convertPEMToBytes(pem: string): Uint8Array {
  const certBase64 = pem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/\n/g, '');

  return isoBase64URL.toBuffer(certBase64, 'base64');
}
