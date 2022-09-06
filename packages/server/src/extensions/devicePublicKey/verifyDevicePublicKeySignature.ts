import base64url from "base64url";
import { toHash } from "../../helpers/toHash";
import { verifySignature } from "../../helpers/verifySignature";
import { DevicePublicKeyAuthenticatorOutput } from "../../helpers/decodeAuthenticatorExtensions";
import {
  AuthenticationCredentialJSON,
  AuthenticatorAssertionResponseJSON,
  RegistrationCredentialJSON,
  AuthenticatorAttestationResponseJSON
} from "@simplewebauthn/typescript-types";
import { decodeAttestationObject } from "../../helpers/decodeAttestationObject";

export type VerifyDevicePublicKeySignatureOpts = {
  credential: RegistrationCredentialJSON | AuthenticationCredentialJSON
  authenticatorOutput: DevicePublicKeyAuthenticatorOutput;
  signature: Buffer;
};

/**
 * https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/1663.html#sctn-device-publickey-extension-verification-create
 * 3. Verify that `signature` is a valid signature over the assertion signature
 *    input by the device public key *dpk*. (The signature algorithm is the same
 *    as for the user credential.)
 * @param options 
 * @returns Promise<boolean>
 */
export async function verifyDevicePublicKeySignature(
  options: VerifyDevicePublicKeySignatureOpts
): Promise<boolean> {
  const { credential, authenticatorOutput, signature } = options;

  let authData;
  if (isAuthenticationResponse(credential)) {
    const { authenticatorData } = credential.response;
    authData = base64url.toBuffer(authenticatorData);
  } else if (isRegistrationResponse(credential)) {
    const attestationObject = base64url.toBuffer(credential.response.attestationObject);
    const { authData: authenticatorData } = decodeAttestationObject(attestationObject);
    authData = authenticatorData;
  }
  if (authData === undefined) {
    throw new Error("AuthenticatorResponse doesn't include authenticatorData");
  }

  const { clientDataJSON } = credential.response;
  const clientDataHash = toHash(base64url.toBuffer(clientDataJSON));
  
  const nonce = authenticatorOutput.nonce ? authenticatorOutput.nonce : Buffer.from('');
  const signatureBase = Buffer.concat([authData, clientDataHash, nonce]);
  // It's a device public key and not a credential public key, but to align with
  // the `verifySinature` signature, we name it `credentialPublicKey`.
  const credentialPublicKey = authenticatorOutput.dpk;

  return verifySignature({ signature, signatureBase, credentialPublicKey });
}

function isAuthenticationResponse(
  cred: AuthenticationCredentialJSON | RegistrationCredentialJSON 
): cred is AuthenticationCredentialJSON {
  return Object.keys(cred.response as AuthenticatorAssertionResponseJSON).indexOf('authenticatorData') >= 0;
}

function isRegistrationResponse(
  cred: AuthenticationCredentialJSON | RegistrationCredentialJSON 
): cred is RegistrationCredentialJSON {
  return Object.keys(cred.response as  AuthenticatorAttestationResponseJSON).indexOf('attestationObject') >= 0;
}
