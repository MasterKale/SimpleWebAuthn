/**
 * @packageDocumentation
 * @module @simplewebauthn/browser
 */
import startAttestation from './methods/startAttestation';
import startAssertion from './methods/startAssertion';
import supportsWebauthn from './helpers/supportsWebauthn';

export default { startAttestation, startAssertion, supportsWebauthn };
