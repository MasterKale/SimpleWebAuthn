/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 * @preferred
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';
import previewAttestation from './debugging/previewAttestation';
import previewAssertion from './debugging/previewAssertion';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
  // Debugging tools
  previewAttestation,
  previewAssertion,
};
