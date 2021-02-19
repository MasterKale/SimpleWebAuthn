/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions, { GenerateAttestationOptions } from './attestation/generateAttestationOptions';
import generateAssertionOptions, { GenerateAssertionOptions } from './assertion/generateAssertionOptions';
import verifyAttestationResponse, { VerifiedAttestation, VerifyAttestationOptions } from './attestation/verifyAttestationResponse';
import verifyAssertionResponse, { VerifiedAssertion, VerifyAssertionOptions } from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  GenerateAttestationOptions,
  GenerateAssertionOptions,
  VerifyAttestationOptions,
  VerifyAssertionOptions,
  VerifiedAttestation,
  VerifiedAssertion,
  MetadataService,
};