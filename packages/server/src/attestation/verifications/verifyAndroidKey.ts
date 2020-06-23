import type { AttestationStatement } from '../../helpers/decodeAttestationObject';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import verifySignature from '../../helpers/verifySignature';

type Options = {
  authData: Buffer;
  clientDataHash: Buffer;
  attStmt: AttestationStatement;
};

export default function verifyAttestationAndroidKey(options: Options): boolean {
  const { authData, clientDataHash, attStmt } = options;
  const { x5c, sig } = attStmt;

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (AndroidKey)');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (AndroidKey)');
  }

  const signatureBase = Buffer.concat([authData, clientDataHash]);
  const leafCertPEM = convertASN1toPEM(x5c[0]);

  return verifySignature(sig, signatureBase, leafCertPEM);
}
