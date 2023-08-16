// @simplewebauthn/typescript-types
export type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  UserVerificationRequirement,
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  CredentialDeviceType,
  Base64URLString,
  AttestationConveyancePreference,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialParameters,
  RegistrationResponseJSON,
} from '../../typescript-types/src/index.ts';

// @simplewebauthn/iso-webcrypto
export { default as WebCrypto } from '../../iso-webcrypto/src/browser.ts';

// NPM: cross-fetch
export { default as fetch } from 'npm:cross-fetch';

// NPM: debug
export { default as debug, Debugger } from 'npm:debug';

// cbor (a.k.a. cbor-x in Node land)
export * as cborx from 'https://deno.land/x/cbor@v1.5.2/index.js';
