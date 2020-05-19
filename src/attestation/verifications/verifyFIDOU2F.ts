import base64url from 'base64url';

import { AttestationObject, VerifiedAttestation } from '@types';
import toHash from '@helpers/toHash';
import convertCOSEtoPKCS from '@helpers/convertCOSEtoPKCS';
import convertASN1toPEM from '@helpers/convertASN1toPEM';
import verifySignature from '@helpers/verifySignature';

import parseAttestationAuthData from '../parseAttestationAuthData';

/**
 * U2F Presence constant
 */
const U2F_USER_PRESENTED = 0x01;


export default function verifyAttestationFIDOU2F(
  attestationObject: AttestationObject,
  base64ClientDataJSON: string,
): VerifiedAttestation {
  const { fmt, authData, attStmt } = attestationObject;

  const authDataStruct = parseAttestationAuthData(authData);
  const {
    flags,
    COSEPublicKey,
    rpIdHash,
    credentialID,
    counter,
  } = authDataStruct;

  if (!(flags.flagsInt & U2F_USER_PRESENTED)) {
    throw new Error('User was NOT present during authentication');
  }

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
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
    throw new Error('No attestation certificate provided in attestation statement');
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement');
  }

  const publicKeyCertPEM = convertASN1toPEM(x5c[0]);

  const toReturn: VerifiedAttestation = {
    verified: verifySignature(sig, signatureBase, publicKeyCertPEM),
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
