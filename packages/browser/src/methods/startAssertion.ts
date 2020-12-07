import {
  PublicKeyCredentialRequestOptionsJSON,
  AssertionCredential,
  AssertionCredentialJSON,
} from '@simplewebauthn/typescript-types';

import bufferToBase64URLString from '../helpers/bufferToBase64URLString';
import base64URLStringToBuffer from '../helpers/base64URLStringToBuffer';
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

  // We need to avoid passing empty array to avoid blocking retrieval
  // of public key
  let allowCredentials;
  if (requestOptionsJSON.allowCredentials?.length !== 0) {
    allowCredentials = requestOptionsJSON.allowCredentials?.map(toPublicKeyCredentialDescriptor);
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...requestOptionsJSON,
    challenge: base64URLStringToBuffer(requestOptionsJSON.challenge),
    allowCredentials,
  };

  // Wait for the user to complete assertion
  const credential = (await navigator.credentials.get({ publicKey })) as AssertionCredential;

  if (!credential) {
    throw new Error('Assertion was not completed');
  }

  const { id, rawId, response, type } = credential;

  let userHandle = undefined;
  if (response.userHandle) {
    userHandle = bufferToBase64URLString(response.userHandle);
  }

  // Convert values to base64 to make it easier to send back to the server
  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      authenticatorData: bufferToBase64URLString(response.authenticatorData),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      signature: bufferToBase64URLString(response.signature),
      userHandle,
    },
    type,
  };
}
