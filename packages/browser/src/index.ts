/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import { startRegistration } from './methods/startRegistration';
import { startAuthentication } from './methods/startAuthentication';
import { browserSupportsWebAuthn } from './helpers/browserSupportsWebAuthn';
import { platformAuthenticatorIsAvailable } from './helpers/platformAuthenticatorIsAvailable';
import { browserSupportsWebAuthnAutofill } from './helpers/browserSupportsWebAuthnAutofill';
import { base64URLStringToBuffer } from './helpers/base64URLStringToBuffer';
import { bufferToBase64URLString } from './helpers/bufferToBase64URLString';

export {
  base64URLStringToBuffer,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  bufferToBase64URLString,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
};

export type { WebAuthnErrorCode } from './helpers/webAuthnError';
