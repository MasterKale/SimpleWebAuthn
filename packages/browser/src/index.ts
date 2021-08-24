/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import startAttestation from './methods/startAttestation';
import startAssertion from './methods/startAssertion';
import { browserSupportsWebauthn } from './helpers/browserSupportsWebauthn';
import { platformAuthenticatorIsAvailable } from './helpers/platformAuthenticatorIsAvailable';

export {
  startAttestation,
  startAssertion,
  browserSupportsWebauthn,
  platformAuthenticatorIsAvailable,
};
