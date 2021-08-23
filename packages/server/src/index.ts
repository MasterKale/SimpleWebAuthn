/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import generateRegistrationOptions from './registration/generateRegistrationOptions';
import verifyRegistrationResponse from './registration/verifyRegistrationResponse';
import generateAssertionOptions from './authentication/generateAuthenticationOptions';
import verifyAssertionResponse from './authentication/verifyAuthenticationResponse';
import MetadataService from './services/metadataService';
import SettingsService from './services/settingsService';

export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
  SettingsService,
};

import type { GenerateRegistrationOptionsOpts } from './registration/generateRegistrationOptions';
import type { GenerateAssertionOptionsOpts } from './authentication/generateAuthenticationOptions';
import type { MetadataStatement } from './services/metadataService';
import type {
  VerifiedAttestation,
  VerifyRegistrationResponseOpts,
} from './registration/verifyRegistrationResponse';
import type {
  VerifiedAssertion,
  VerifyAssertionResponseOpts,
} from './authentication/verifyAuthenticationResponse';

export type {
  GenerateRegistrationOptionsOpts,
  GenerateAssertionOptionsOpts,
  MetadataStatement,
  VerifyRegistrationResponseOpts,
  VerifyAssertionResponseOpts,
  VerifiedAttestation,
  VerifiedAssertion,
};
