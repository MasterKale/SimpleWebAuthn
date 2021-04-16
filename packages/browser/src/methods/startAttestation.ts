import {
  PublicKeyCredentialCreationOptionsJSON,
  AttestationCredential,
  AttestationCredentialJSON,
} from '@simplewebauthn/typescript-types';

import stringToArrayBuffer from '../helpers/stringToArrayBuffer';
import bufferToBase64URLString from '../helpers/bufferToBase64URLString';
import base64URLStringToBuffer from '../helpers/base64URLStringToBuffer';
import supportsWebauthn from '../helpers/supportsWebauthn';
import toPublicKeyCredentialDescriptor from '../helpers/toPublicKeyCredentialDescriptor';

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param creationOptionsJSON Output from @simplewebauthn/server's generateAttestationOptions(...)
 */
export default async function startAttestation(
  creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<AttestationCredentialJSON> {
  if (!supportsWebauthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...creationOptionsJSON,
    challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
    user: {
      ...creationOptionsJSON.user,
      id: stringToArrayBuffer(creationOptionsJSON.user.id),
    },
    excludeCredentials: creationOptionsJSON.excludeCredentials.map(toPublicKeyCredentialDescriptor),
  };

  // Wait for the user to complete attestation
  const credential = (await navigator.credentials.create({ publicKey })) as AttestationCredential;

  if (!credential) {
    throw new Error('Attestation was not completed');
  }

  const { id, rawId, response, type } = credential;

  // Convert values to base64 to make it easier to send back to the server
  const credentialJSON: AttestationCredentialJSON = {
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
