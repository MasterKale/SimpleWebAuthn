import base64url from 'base64url';
import type { Base64URLString } from '@simplewebauthn/typescript-types';

/**
 * Convert X.509 certificate to an OpenSSL-compatible PEM text format.
 *
 * @param buffer - Cert or PubKey buffer
 * @return PEM
 */
export default function convertX509CertToPEM(pkBuffer: Buffer | Base64URLString): string {
  let buffer: Buffer;
  if (typeof pkBuffer === 'string') {
    buffer = base64url.toBuffer(pkBuffer);
  } else {
    buffer = pkBuffer;
  }

  let type;
  if (buffer.length === 65 && buffer[0] === 0x04) {
    /**
     * If needed, we encode rawpublic key to ASN structure, adding metadata:
     *
     * SEQUENCE {
     *   SEQUENCE {
     *     OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
     *     OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
     *   }
     *   BITSTRING <raw public key>
     * }
     *
     * Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is
     * constant).
     */
    buffer = Buffer.concat([
      Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
      buffer,
    ]);

    type = 'PUBLIC KEY';
  } else {
    type = 'CERTIFICATE';
  }

  const b64cert = buffer.toString('base64');

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;

    PEMKey += `${b64cert.substr(start, 64)}\n`;
  }

  PEMKey = `-----BEGIN ${type}-----\n${PEMKey}-----END ${type}-----\n`;

  return PEMKey;
}
