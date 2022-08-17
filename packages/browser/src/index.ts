/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import { startRegistration } from './methods/startRegistration';
import { startAuthentication } from './methods/startAuthentication';
import { browserSupportsWebAuthn } from './helpers/browserSupportsWebAuthn';
import { platformAuthenticatorIsAvailable } from './helpers/platformAuthenticatorIsAvailable';
import { browserSupportsWebAuthnAutofill } from './helpers/browserSupportsWebAuthnAutofill';

export {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
};
