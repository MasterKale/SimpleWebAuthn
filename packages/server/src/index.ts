/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions, {
  GenerateAttestationOptions,
} from './attestation/generateAttestationOptions';
import verifyAttestationResponse, {
  VerifyAttestationResponseOptions,
  VerifiedAttestation,
} from './attestation/verifyAttestationResponse';
import generateAssertionOptions, {
  GenerateAssertionOptions,
} from './assertion/generateAssertionOptions';
import verifyAssertionResponse, {
  VerifyAssertionResponseOptions,
  VerifiedAssertion,
} from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';
import { ATTESTATION_FORMATS } from './helpers/decodeAttestationObject';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
  GenerateAttestationOptions,
  VerifyAttestationResponseOptions,
  GenerateAssertionOptions,
  VerifyAssertionResponseOptions,
  VerifiedAssertion,
  VerifiedAttestation,
  ATTESTATION_FORMATS,
};
