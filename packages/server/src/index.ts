/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import { generateRegistrationOptions } from './registration/generateRegistrationOptions.js';
import { verifyRegistrationResponse } from './registration/verifyRegistrationResponse.js';
import { generateAuthenticationOptions } from './authentication/generateAuthenticationOptions.js';
import { verifyAuthenticationResponse } from './authentication/verifyAuthenticationResponse.js';
import { MetadataService } from './services/metadataService.js';
import { SettingsService } from './services/settingsService.js';

export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions as generateAuthenticationOptions,
  verifyAuthenticationResponse,
  MetadataService,
  SettingsService,
};

import type { GenerateRegistrationOptionsOpts } from './registration/generateRegistrationOptions.js';
import type { GenerateAuthenticationOptionsOpts } from './authentication/generateAuthenticationOptions.js';
import type { MetadataStatement } from './metadata/mdsTypes.js';
import type {
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from './registration/verifyRegistrationResponse.js';
import type {
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from './authentication/verifyAuthenticationResponse.js';

export type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  MetadataStatement,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
};
