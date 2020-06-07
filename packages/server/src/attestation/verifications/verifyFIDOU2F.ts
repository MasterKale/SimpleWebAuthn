import type { AttestationStatement } from '../../helpers/decodeAttestationObject';

import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import verifySignature from '../../helpers/verifySignature';

type Options = {
  attStmt: AttestationStatement;
  clientDataHash: Buffer;
  rpIdHash: Buffer;
  credentialID: Buffer;
  credentialPublicKey: Buffer;
};

/**
 * Verify an attestation response with fmt 'fido-u2f'
 */
export default function verifyAttestationFIDOU2F(options: Options): boolean {
  const { attStmt, clientDataHash, rpIdHash, credentialID, credentialPublicKey } = options;

  const reservedByte = Buffer.from([0x00]);
  const publicKey = convertCOSEtoPKCS(credentialPublicKey);

  const signatureBase = Buffer.concat([
    reservedByte,
    rpIdHash,
    clientDataHash,
    credentialID,
    publicKey,
  ]);

  const { sig, x5c } = attStmt;

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (FIDOU2F)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (FIDOU2F)');
  }

  const publicKeyCertPEM = convertASN1toPEM(x5c[0]);

  return verifySignature(sig, signatureBase, publicKeyCertPEM);
}
