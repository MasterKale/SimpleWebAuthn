/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import { startRegistration } from './methods/startRegistration';
import { startAuthentication } from './methods/startAuthentication';
import { browserSupportsWebauthn } from './helpers/browserSupportsWebauthn';
import { platformAuthenticatorIsAvailable } from './helpers/platformAuthenticatorIsAvailable';

export {
  startRegistration,
  startAuthentication,
  browserSupportsWebauthn,
  platformAuthenticatorIsAvailable,
};
