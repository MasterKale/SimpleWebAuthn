import base64url from 'base64url';

import type { AttestationObject } from '../../helpers/decodeAttestationObject';
import type { VerifiedAttestation } from '../verifyAttestationResponse';

import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';
import parseAuthenticatorData from '../../helpers/parseAuthenticatorData';

/**
 * Verify an attestation response with fmt 'none'
 *
 * This is the weaker of the attestations, so there are only so many checks we can perform
 */
export default function verifyAttestationNone(
  attestationObject: AttestationObject,
): VerifiedAttestation {
  const { fmt, authData } = attestationObject;
  const authDataStruct = parseAuthenticatorData(authData);

  const { credentialID, COSEPublicKey, counter, flags } = authDataStruct;

  if (!flags.up) {
    throw new Error('User was not present for attestation (None)');
  }

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator (None)');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator (None)');
  }

  const publicKey = convertCOSEtoPKCS(COSEPublicKey);

  const toReturn: VerifiedAttestation = {
    verified: true,
    userVerified: flags.uv,
    authenticatorInfo: {
      fmt,
      counter,
      base64PublicKey: base64url.encode(publicKey),
      base64CredentialID: base64url.encode(credentialID),
    },
  };

  return toReturn;
}
