/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
};
