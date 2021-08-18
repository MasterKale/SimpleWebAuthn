/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateAttestationOptions from './attestation/generateAttestationOptions';
import verifyAttestationResponse from './attestation/verifyAttestationResponse';
import generateAssertionOptions from './assertion/generateAssertionOptions';
import verifyAssertionResponse from './assertion/verifyAssertionResponse';
import MetadataService from './services/metadataService';
import SettingsService from './services/settingsService';

export {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
  SettingsService,
};

import type { GenerateAttestationOptionsOpts } from './attestation/generateAttestationOptions';
import type { GenerateAssertionOptionsOpts } from './assertion/generateAssertionOptions';
import type { MetadataStatement } from './services/metadataService';
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
  MetadataStatement,
  VerifyAttestationResponseOpts,
  VerifyAssertionResponseOpts,
  VerifiedAttestation,
  VerifiedAssertion,
};
