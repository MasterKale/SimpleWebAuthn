import base64url from 'base64url';

import type { AttestationObject } from '../../helpers/decodeAttestationObject';
import type { ParsedAuthenticatorData } from '../../helpers/parseAuthenticatorData';
import type { VerifiedAttestation } from '../verifyAttestationResponse';

import toHash from '../../helpers/toHash';
import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';
import convertASN1toPEM from '../../helpers/convertASN1toPEM';
import verifySignature from '../../helpers/verifySignature';

/**
 * Verify an attestation response with fmt 'fido-u2f'
 */
export default function verifyAttestationFIDOU2F(
  attestationObject: AttestationObject,
  base64ClientDataJSON: string,
  parsedAuthData: ParsedAuthenticatorData,
): VerifiedAttestation {
  const { fmt, attStmt } = attestationObject;
  const { flags, COSEPublicKey, rpIdHash, credentialID, counter } = parsedAuthData;

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator (FIDOU2F)');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator (FIDOU2F)');
  }

  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));
  const reservedByte = Buffer.from([0x00]);
  const publicKey = convertCOSEtoPKCS(COSEPublicKey);

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

  const toReturn: VerifiedAttestation = {
    verified: verifySignature(sig, signatureBase, publicKeyCertPEM),
    userVerified: flags.uv,
  };

  if (toReturn.verified) {
    toReturn.authenticatorInfo = {
      fmt,
      counter,
      base64PublicKey: base64url.encode(publicKey),
      base64CredentialID: base64url.encode(credentialID),
    };
  }

  return toReturn;
}
