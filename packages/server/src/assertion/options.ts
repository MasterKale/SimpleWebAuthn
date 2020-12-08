import {
  AssertionCredentialJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticatorDevice,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import EmptyAdapter from '../adapters/EmptyAdapter';

export interface GenerateAssertionOptions {
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
  challenge?: string | Buffer;
  timeout?: number;
  adapters?: EmptyAdapter[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
}

export type VerifyAssertionOptions = {
  credential: AssertionCredentialJSON;
  expectedChallenge?: string;
  expectedOrigin?: string;
  expectedRPID?: string;
  adapters?: EmptyAdapter[];
  authenticator: AuthenticatorDevice;
  fidoUserVerification?: UserVerificationRequirement;
};
