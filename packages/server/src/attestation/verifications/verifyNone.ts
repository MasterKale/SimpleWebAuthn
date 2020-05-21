import base64url from 'base64url';
import { AttestationObject, VerifiedAttestation } from "@webauthntine/typescript-types";

import convertCOSEtoPKCS from "@helpers/convertCOSEtoPKCS";

import parseAttestationAuthData from '../parseAttestationAuthData';


/**
 * Verify an attestation response with fmt 'none'
 *
 * This is the weaker of the assertions, so there are only so many checks we can perform
 */
export default function verifyAttestationNone(
  attestationObject: AttestationObject,
): VerifiedAttestation {
  const { fmt, authData } = attestationObject;
  const authDataStruct = parseAttestationAuthData(authData);

  console.log('authDataStruct:', authDataStruct);

  const {
    credentialID,
    COSEPublicKey,
    counter,
    flags,
  } = authDataStruct;

  if (!COSEPublicKey) {
    throw new Error('No public key was provided by authenticator');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
  }

  // Make sure the (U)ser (P)resent for the attestation
  if (!flags.up) {
    console.error('User was not Present for attestation');
    console.debug('attestation\'s flags:', flags);
    throw new Error('User presence could not be verified');
  }

  if (!flags.uv) {
    console.warn('The authenticator could not uniquely Verify the user');
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
