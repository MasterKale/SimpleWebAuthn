import {
  AuthenticationCredential,
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';

import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn';
import { browserSupportsWebAuthnAutofill } from '../helpers/browserSupportsWebAuthnAutofill';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyAuthenticationError } from '../helpers/identifyAuthenticationError';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment';

export type StartAuthenticationOpts = {
  optionsJSON: PublicKeyCredentialRequestOptionsJSON;
  useBrowserAutofill?: boolean;
  verifyBrowserAutofillInput?: boolean;
};

/**
 * Begin authenticator "login" via WebAuthn assertion
 *
 * @param optionsJSON Output from **@simplewebauthn/server**'s `generateAuthenticationOptions()`
 * @param useBrowserAutofill (Optional) Initialize conditional UI to enable logging in via browser autofill prompts. Defaults to `false`.
 * @param verifyBrowserAutofillInput (Optional) Ensure a suitable `<input>` element is present when `useBrowserAutofill` is `true`. Defaults to `true`.
 */
export async function startAuthentication(
  options: StartAuthenticationOpts,
): Promise<AuthenticationResponseJSON> {
  const {
    optionsJSON,
    useBrowserAutofill = false,
    verifyBrowserAutofillInput = true,
  } = options;

  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to avoid passing empty array to avoid blocking retrieval
  // of public key
  let allowCredentials;
  if (optionsJSON.allowCredentials?.length !== 0) {
    allowCredentials = optionsJSON.allowCredentials?.map(
      toPublicKeyCredentialDescriptor,
    );
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...optionsJSON,
    challenge: base64URLStringToBuffer(optionsJSON.challenge),
    allowCredentials,
  };

  // Prepare options for `.get()`
  const getOptions: CredentialRequestOptions = {};

  /**
   * Set up the page to prompt the user to select a credential for authentication via the browser's
   * input autofill mechanism.
   */
  if (useBrowserAutofill) {
    if (!(await browserSupportsWebAuthnAutofill())) {
      throw Error('Browser does not support WebAuthn autofill');
    }

    // Check for an <input> with "webauthn" in its `autocomplete` attribute
    const eligibleInputs = document.querySelectorAll(
      "input[autocomplete$='webauthn']",
    );

    // WebAuthn autofill requires at least one valid input
    if (eligibleInputs.length < 1 && verifyBrowserAutofillInput) {
      throw Error(
        'No <input> with "webauthn" as the only or last value in its `autocomplete` attribute was detected',
      );
    }

    // `CredentialMediationRequirement` doesn't know about "conditional" yet as of
    // typescript@4.6.3
    getOptions.mediation = 'conditional' as CredentialMediationRequirement;
    // Conditional UI requires an empty allow list
    publicKey.allowCredentials = [];
  }

  // Finalize options
  getOptions.publicKey = publicKey;
  // Set up the ability to cancel this request if the user attempts another
  getOptions.signal = WebAuthnAbortService.createNewAbortSignal();

  // Wait for the user to complete assertion
  let credential;
  try {
    credential = (await navigator.credentials.get(getOptions)) as AuthenticationCredential;
  } catch (err) {
    throw identifyAuthenticationError({ error: err as Error, options: getOptions });
  }

  if (!credential) {
    throw new Error('Authentication was not completed');
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
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: toAuthenticatorAttachment(
      credential.authenticatorAttachment,
    ),
  };
}
