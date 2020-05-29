/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 * @preferred
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
};
