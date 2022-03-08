import {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationCredential,
  RegistrationCredentialJSON,
} from '@simplewebauthn/typescript-types';

import utf8StringToBuffer from '../helpers/utf8StringToBuffer';
import bufferToBase64URLString from '../helpers/bufferToBase64URLString';
import base64URLStringToBuffer from '../helpers/base64URLStringToBuffer';
import { browserSupportsWebauthn } from '../helpers/browserSupportsWebauthn';
import toPublicKeyCredentialDescriptor from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyRegistrationError } from '../helpers/identifyRegistrationError';

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param creationOptionsJSON Output from @simplewebauthn/server's generateRegistrationOptions(...)
 */
export default async function startRegistration(
  creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationCredentialJSON> {
  if (!browserSupportsWebauthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...creationOptionsJSON,
    challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
    user: {
      ...creationOptionsJSON.user,
      id: utf8StringToBuffer(creationOptionsJSON.user.id),
    },
    excludeCredentials: creationOptionsJSON.excludeCredentials.map(toPublicKeyCredentialDescriptor),
  };

  const options: CredentialCreationOptions = { publicKey };

  // Wait for the user to complete attestation
  let credential;
  try {
    credential = (await navigator.credentials.create(options)) as RegistrationCredential;
  } catch (err) {
    throw identifyRegistrationError({ error: err as Error, options });
  }

  if (!credential) {
    throw new Error('Registration was not completed');
  }

  const { id, rawId, response, type } = credential;

  // Convert values to base64 to make it easier to send back to the server
  const credentialJSON: RegistrationCredentialJSON = {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
  };

  /**
   * Include the authenticator's transports if the browser supports querying for them
   */
  if (typeof response.getTransports === 'function') {
    credentialJSON.transports = response.getTransports();
  }

  return credentialJSON;
}
