/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';
import * as Adapters from './adapters';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
  Adapters,
};
