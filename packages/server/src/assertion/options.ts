import {
  AssertionCredentialJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticatorDevice,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import Adapter from '../adapters/Adapter';

export interface GenerateAssertionOptions {
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
  challenge?: string | Buffer;
  timeout?: number;
  adapters?: Adapter[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
}

export type VerifyAssertionOptions = {
  credential: AssertionCredentialJSON;
  expectedChallenge?: string;
  expectedOrigin?: string;
  expectedRPID?: string;
  adapters?: Adapter[];
  authenticator: AuthenticatorDevice;
  fidoUserVerification?: UserVerificationRequirement;
};
