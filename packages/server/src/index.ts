/**
 * @packageDocumentation
 * @module @simplewebauthn/server
 */
import { generateRegistrationOptions } from "./registration/generateRegistrationOptions.ts";
import { verifyRegistrationResponse } from "./registration/verifyRegistrationResponse.ts";
import { generateAuthenticationOptions } from "./authentication/generateAuthenticationOptions.ts";
import { verifyAuthenticationResponse } from "./authentication/verifyAuthenticationResponse.ts";
import { MetadataService } from "./services/metadataService.ts";
import { SettingsService } from "./services/settingsService.ts";

export {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  MetadataService,
  SettingsService,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
};

import type { GenerateRegistrationOptionsOpts } from "./registration/generateRegistrationOptions.ts";
import type { GenerateAuthenticationOptionsOpts } from "./authentication/generateAuthenticationOptions.ts";
import type { MetadataStatement } from "./metadata/mdsTypes.ts";
import type {
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from "./registration/verifyRegistrationResponse.ts";
import type {
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from "./authentication/verifyAuthenticationResponse.ts";

export type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  MetadataStatement,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
};
