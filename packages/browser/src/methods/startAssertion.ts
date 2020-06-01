import {
  PublicKeyCredentialRequestOptionsJSON,
  AssertionCredential,
  AssertionCredentialJSON,
} from '@simplewebauthn/typescript-types';

import toUint8Array from '../helpers/toUint8Array';
import toBase64String from '../helpers/toBase64String';
import supportsWebauthn from '../helpers/supportsWebauthn';
import toPublicKeyCredentialDescriptor from '../helpers/toPublicKeyCredentialDescriptor';

/**
 * Begin authenticator "login" via WebAuthn assertion
 *
 * @param requestOptionsJSON Output from @simplewebauthn/server's generateAssertionOptions(...)
 */
export default async function startAssertion(
  requestOptionsJSON: PublicKeyCredentialRequestOptionsJSON,
): Promise<AssertionCredentialJSON> {
  if (!supportsWebauthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...requestOptionsJSON,
    challenge: toUint8Array(requestOptionsJSON.challenge),
    allowCredentials: requestOptionsJSON.allowCredentials.map(
      toPublicKeyCredentialDescriptor,
    ),
  };

  // Wait for the user to complete assertion
  const credential = await navigator.credentials.get({ publicKey }) as AssertionCredential;

  if (!credential) {
    throw new Error('Assertion was not completed');
  }

  const { rawId, response } = credential;

  let userHandle = undefined;
  if (response.userHandle) {
    userHandle = toBase64String(response.userHandle);
  }

  // Convert values to base64 to make it easier to send back to the server
  return {
    ...credential,
    rawId: toBase64String(rawId),
    response: {
      ...response,
      authenticatorData: toBase64String(response.authenticatorData),
      clientDataJSON: toBase64String(response.clientDataJSON),
      signature: toBase64String(response.signature),
      userHandle,
    },
  };
}
