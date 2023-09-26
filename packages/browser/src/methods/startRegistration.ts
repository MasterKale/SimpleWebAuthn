import {
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationCredential,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';

import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyRegistrationError } from '../helpers/identifyRegistrationError';
import { webauthnAbortService } from '../helpers/webAuthnAbortService';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment';

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param creationOptionsJSON Output from **@simplewebauthn/server**'s `generateRegistrationOptions()`
 */
export async function startRegistration(
  creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...creationOptionsJSON,
    challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
    user: {
      ...creationOptionsJSON.user,
      id: base64URLStringToBuffer(creationOptionsJSON.user.id),
    },
    excludeCredentials: creationOptionsJSON.excludeCredentials?.map(
      toPublicKeyCredentialDescriptor,
    ),
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

  // Continue to play it safe with `getTransports()` for now, even when L3 types say it's required
  let transports: AuthenticatorTransportFuture[] | undefined = undefined;
  if (typeof response.getTransports === 'function') {
    transports = response.getTransports();
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responsePublicKeyAlgorithm: number | undefined = undefined;
  if (typeof response.getPublicKeyAlgorithm === 'function') {
    responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
  }

  let responsePublicKey: string | undefined = undefined;
  if (typeof response.getPublicKey === 'function') {
    const _publicKey = response.getPublicKey();
    if (_publicKey !== null) {
      responsePublicKey = bufferToBase64URLString(_publicKey);
    }
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responseAuthenticatorData: string | undefined;
  if (typeof response.getAuthenticatorData === 'function') {
    responseAuthenticatorData = bufferToBase64URLString(
      response.getAuthenticatorData(),
    );
  }

  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      transports,
      publicKeyAlgorithm: responsePublicKeyAlgorithm,
      publicKey: responsePublicKey,
      authenticatorData: responseAuthenticatorData,
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: toAuthenticatorAttachment(
      credential.authenticatorAttachment,
    ),
  };
}
