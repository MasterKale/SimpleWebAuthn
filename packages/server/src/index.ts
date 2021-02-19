/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import { generateAttestationOptions, GenerateAttestationOptions } from './attestation/generateAttestationOptions';
import { generateAssertionOptions, GenerateAssertionOptions } from './assertion/generateAssertionOptions';
import { verifyAttestationResponse, VerifyAttestationOptions, VerifiedAttestation } from './attestation/verifyAttestationResponse';
import { verifyAssertionResponse, VerifyAssertionOptions, VerifiedAssertion } from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  GenerateAssertionOptions,
  GenerateAttestationOptions,
  VerifyAttestationOptions,
  VerifyAssertionOptions,
  VerifiedAttestation,
  VerifiedAssertion,
  MetadataService,
};
