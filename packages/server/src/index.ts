/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import { generateRegistrationOptions } from './registration/generateRegistrationOptions';
import { verifyRegistrationResponse } from './registration/verifyRegistrationResponse';
import { generateAuthenticationOptions } from './authentication/generateAuthenticationOptions';
import { verifyAuthenticationResponse } from './authentication/verifyAuthenticationResponse';
import { MetadataService } from './services/metadataService';
import { SettingsService } from './services/settingsService';

export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions as generateAuthenticationOptions,
  verifyAuthenticationResponse,
  MetadataService,
  SettingsService,
};

import type { GenerateRegistrationOptionsOpts } from './registration/generateRegistrationOptions';
import type { GenerateAuthenticationOptionsOpts } from './authentication/generateAuthenticationOptions';
import type { MetadataStatement } from './metadata/mdsTypes';
import type {
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from './registration/verifyRegistrationResponse';
import type {
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from './authentication/verifyAuthenticationResponse';

export type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  MetadataStatement,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
};
