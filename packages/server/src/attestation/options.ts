import {
  AttestationConveyancePreference,
  AttestationCredentialJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialDescriptorJSON,
} from '@simplewebauthn/typescript-types';
import EmptyAdapter from 'adapters/EmptyAdapter';

export interface GenerateAttestationOptions {
  adapters?: EmptyAdapter[];
  rpName: string;
  rpID: string;
  userID: string;
  userName: string;
  challenge?: string | Buffer;
  userDisplayName?: string;
  timeout?: number;
  attestationType?: AttestationConveyancePreference;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  extensions?: AuthenticationExtensionsClientInputs;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
}

export interface VerifyAttestationOptions {
  adapters?: EmptyAdapter[];
  credential: AttestationCredentialJSON;
  expectedChallenge?: string;
  expectedOrigin?: string;
  expectedRPID?: string;
  requireUserVerification?: boolean;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
}
