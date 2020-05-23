import {
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticatorAssertionResponseJSON,
  AssertionCredential,
} from '@webauthntine/typescript-types';
import base64js from 'base64-js';

import toUint8Array from '../helpers/toUint8Array';
import toBase64String from '../helpers/toBase64String';
import supportsWebauthn from '../helpers/supportsWebauthn';

/**
 * Begin authenticator "login" via WebAuthn assertion
 *
 * @param requestOptionsJSON Output from @webauthntine/server's generateAssertionOptions(...)
 */
export default async function startAssertion(
  requestOptionsJSON: PublicKeyCredentialRequestOptionsJSON
): Promise<AuthenticatorAssertionResponseJSON> {
  if (!supportsWebauthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...requestOptionsJSON.publicKey,
    challenge: toUint8Array(requestOptionsJSON.publicKey.challenge),
    allowCredentials: requestOptionsJSON.publicKey.allowCredentials.map((cred) => {
      // Make sure the credential ID length is a multiple of 4
      let id = cred.id.padEnd(cred.id.length + (cred.id.length % 4), '=');

      return {
        ...cred,
        id: base64js.toByteArray(id),
      };
    })
  };

  // Wait for the user to complete assertion
  const credential = await navigator.credentials.get({ publicKey });

  if (!credential) {
    throw new Error('Assertion was not completed');
  }

  const { response } = (credential as AssertionCredential);

  let base64UserHandle = undefined;
  if (response.userHandle) {
    base64UserHandle = toBase64String(response.userHandle);
  }

  // Convert values to base64 to make it easier to send back to the server
  return {
    base64CredentialID: credential.id,
    base64AuthenticatorData: toBase64String(response.authenticatorData),
    base64ClientDataJSON: toBase64String(response.clientDataJSON),
    base64Signature: toBase64String(response.signature),
    base64UserHandle,
  };
}
