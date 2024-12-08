/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import { startRegistration } from './methods/startRegistration.ts';
import { startAuthentication } from './methods/startAuthentication.ts';
import { browserSupportsWebAuthn } from './helpers/browserSupportsWebAuthn.ts';
import { platformAuthenticatorIsAvailable } from './helpers/platformAuthenticatorIsAvailable.ts';
import { browserSupportsWebAuthnAutofill } from './helpers/browserSupportsWebAuthnAutofill.ts';
import { base64URLStringToBuffer } from './helpers/base64URLStringToBuffer.ts';
import { bufferToBase64URLString } from './helpers/bufferToBase64URLString.ts';
import { WebAuthnAbortService } from './helpers/webAuthnAbortService.ts';
import { WebAuthnError } from './helpers/webAuthnError.ts';

export {
  base64URLStringToBuffer,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  bufferToBase64URLString,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
  WebAuthnError,
};

export type { WebAuthnErrorCode } from './helpers/webAuthnError.ts';

export * from './types/index.ts';
