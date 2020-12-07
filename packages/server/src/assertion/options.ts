import {
  AssertionCredentialJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticatorDevice,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';
import BaseAdapter from '../adapters/BaseAdapter';

export interface GenerateAssertionOptions {
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
  challenge?: string | Buffer;
  timeout?: number;
  adapters?: BaseAdapter[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
}

export type VerifyAssertionOptions = {
  credential: AssertionCredentialJSON;
  expectedChallenge?: string;
  expectedOrigin?: string;
  expectedRPID?: string;
  adapters?: BaseAdapter[];
  authenticator: AuthenticatorDevice;
  fidoUserVerification?: UserVerificationRequirement;
};
