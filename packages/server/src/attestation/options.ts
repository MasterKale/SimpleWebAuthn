import {
  AttestationConveyancePreference,
  AttestationCredentialJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialDescriptorJSON,
} from '@simplewebauthn/typescript-types';
import Adapter from 'adapters/Adapter';

export interface GenerateAttestationOptions {
  adapters?: Adapter[];
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
  adapters?: Adapter[];
  credential: AttestationCredentialJSON;
  expectedChallenge?: string;
  expectedOrigin?: string;
  expectedRPID?: string;
  requireUserVerification?: boolean;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
}
