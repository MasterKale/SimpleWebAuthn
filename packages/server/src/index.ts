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
import { verifyDpkSignature } from 'extensions/devicePublicKey/verifyDpkSignature';
import { verifyDevicePublicKey } from 'extensions/devicePublicKey/verifyDevicePublicKey';
import { DevicePublicKeyAuthenticatorOutput } from 'helpers/decodeAuthenticatorExtensions';

export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions as generateAuthenticationOptions,
  verifyAuthenticationResponse,
  MetadataService,
  SettingsService,
  verifyDpkSignature,
  verifyDevicePublicKey,
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
  DevicePublicKeyAuthenticatorOutput,
};
