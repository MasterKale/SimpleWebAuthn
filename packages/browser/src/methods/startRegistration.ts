import {
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationCredential,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';

import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyRegistrationError } from '../helpers/identifyRegistrationError';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment';

export type StartRegistrationOpts = {
  optionsJSON: PublicKeyCredentialCreationOptionsJSON;
  useAutoRegister?: boolean;
};

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param optionsJSON Output from **@simplewebauthn/server**'s `generateRegistrationOptions()`
 * @param useAutoRegister (Optional) Try to silently create a passkey with the password manager that the user just signed in with. Defaults to `false`.
 */
export async function startRegistration(
  options: StartRegistrationOpts,
): Promise<RegistrationResponseJSON> {
  const { optionsJSON, useAutoRegister = false } = options;

  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...optionsJSON,
    challenge: base64URLStringToBuffer(optionsJSON.challenge),
    user: {
      ...optionsJSON.user,
      id: base64URLStringToBuffer(optionsJSON.user.id),
    },
    excludeCredentials: optionsJSON.excludeCredentials?.map(
      toPublicKeyCredentialDescriptor,
    ),
  };

  // Prepare options for `.create()`
  const createOptions: CredentialCreationOptions = {};

  /**
   * Try to use conditional create to register a passkey for the user with the password manager
   * the user just used to authenticate with. The user won't be shown any prominent UI by the
   * browser.
   */
  if (useAutoRegister) {
    // @ts-ignore: `mediation` doesn't yet exist on CredentialCreationOptions but it's possible as of Sept 2024
    createOptions.mediation = 'conditional' as CredentialMediationRequirement;
  }

  // Finalize options
  createOptions.publicKey = publicKey;
  // Set up the ability to cancel this request if the user attempts another
  createOptions.signal = WebAuthnAbortService.createNewAbortSignal();

  // Wait for the user to complete attestation
  let credential;
  try {
    credential = (await navigator.credentials.create(createOptions)) as RegistrationCredential;
  } catch (err) {
    throw identifyRegistrationError({ error: err as Error, options: createOptions });
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
    try {
      responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
    } catch (error) {
      warnOnBrokenImplementation('getPublicKeyAlgorithm()', error as Error);
    }
  }

  let responsePublicKey: string | undefined = undefined;
  if (typeof response.getPublicKey === 'function') {
    try {
      const _publicKey = response.getPublicKey();
      if (_publicKey !== null) {
        responsePublicKey = bufferToBase64URLString(_publicKey);
      }
    } catch (error) {
      warnOnBrokenImplementation('getPublicKey()', error as Error);
    }
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responseAuthenticatorData: string | undefined;
  if (typeof response.getAuthenticatorData === 'function') {
    try {
      responseAuthenticatorData = bufferToBase64URLString(
        response.getAuthenticatorData(),
      );
    } catch (error) {
      warnOnBrokenImplementation('getAuthenticatorData()', error as Error);
    }
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

/**
 * Visibly warn when we detect an issue related to a passkey provider intercepting WebAuthn API
 * calls
 */
function warnOnBrokenImplementation(methodName: string, cause: Error): void {
  console.warn(
    `The browser extension that intercepted this WebAuthn API call incorrectly implemented ${methodName}. You should report this error to them.\n`,
    cause,
  );
}
