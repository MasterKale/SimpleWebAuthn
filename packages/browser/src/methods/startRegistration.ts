import {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationCredential,
  RegistrationCredentialJSON,
} from '@simplewebauthn/typescript-types';

import { utf8StringToBuffer } from '../helpers/utf8StringToBuffer';
import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyRegistrationError } from '../helpers/identifyRegistrationError';
import { webauthnAbortService } from '../helpers/webAuthnAbortService';
import { parseClientExtensionResults } from '../helpers/parseClientExtensionResults';

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param creationOptionsJSON Output from @simplewebauthn/server's generateRegistrationOptions(...)
 */
export async function startRegistration(
  creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationCredentialJSON> {
  if (!browserSupportsWebAuthn()) {
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

  // Finalize options
  const options: CredentialCreationOptions = { publicKey };
  // Set up the ability to cancel this request if the user attempts another
  options.signal = webauthnAbortService.createNewAbortSignal();

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
    clientExtensionResults: parseClientExtensionResults(credential),
    authenticatorAttachment: credential.authenticatorAttachment,
  };

  /**
   * Include the authenticator's transports if the browser supports querying for them
   */
  if (typeof response.getTransports === 'function') {
    credentialJSON.transports = response.getTransports();
  }

  return credentialJSON;
}
