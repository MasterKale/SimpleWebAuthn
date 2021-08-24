/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import startAttestation from './methods/startAttestation';
import startAssertion from './methods/startAssertion';
import { browserSupportsWebauthn } from './helpers/browserSupportsWebauthn';

export { startAttestation, startAssertion, browserSupportsWebauthn };
