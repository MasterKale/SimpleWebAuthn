/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';
import MetadataService from './metadata/metadataService';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
};

import type { GenerateAttestationOptionsOpts } from './attestation/generateAttestationOptions';
import type { GenerateAssertionOptionsOpts } from './assertion/generateAssertionOptions';
import type {
  VerifiedAttestation,
  VerifyAttestationResponseOpts,
} from './attestation/verifyAttestationResponse';
import type {
  VerifiedAssertion,
  VerifyAssertionResponseOpts,
} from './assertion/verifyAssertionResponse';

export type {
  GenerateAttestationOptionsOpts,
  GenerateAssertionOptionsOpts,
  VerifyAttestationResponseOpts,
  VerifyAssertionResponseOpts,
  VerifiedAttestation,
  VerifiedAssertion,
};
