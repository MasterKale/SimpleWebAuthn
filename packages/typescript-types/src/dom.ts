// Generated from typescript@3.9.7 typescript/lib/lib.dom.d.ts
// To regenerate, run the following command from the project root:
// npx lerna --scope=@simplewebauthn/typescript-types exec -- npm run extract-dom-types
export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  readonly authenticatorData: ArrayBuffer;
  readonly signature: ArrayBuffer;
  readonly userHandle: ArrayBuffer | null;
}

export interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
  readonly attestationObject: ArrayBuffer;
}

export interface AuthenticationExtensionsClientInputs {
  appid?: string;
  authnSel?: AuthenticatorSelectionList;
  exts?: boolean;
  loc?: boolean;
  txAuthGeneric?: txAuthGenericArg;
  txAuthSimple?: string;
  uvi?: boolean;
  uvm?: boolean;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredential extends Credential {
  readonly rawId: ArrayBuffer;
  readonly response: AuthenticatorResponse;
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
}

export interface PublicKeyCredentialCreationOptions {
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  challenge: BufferSource;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  extensions?: AuthenticationExtensionsClientInputs;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  rp: PublicKeyCredentialRpEntity;
  timeout?: number;
  user: PublicKeyCredentialUserEntity;
}

export interface PublicKeyCredentialDescriptor {
  id: BufferSource;
  transports?: AuthenticatorTransport[];
  type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialParameters {
  alg: COSEAlgorithmIdentifier;
  type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialRequestOptions {
  allowCredentials?: PublicKeyCredentialDescriptor[];
  challenge: BufferSource;
  extensions?: AuthenticationExtensionsClientInputs;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  displayName: string;
  id: BufferSource;
}

export interface AuthenticatorResponse {
  readonly clientDataJSON: ArrayBuffer;
}

export interface txAuthGenericArg {
  content: ArrayBuffer;
  contentType: string;
}

export interface Credential {
  readonly id: string;
  readonly type: string;
}

export interface AuthenticationExtensionsClientOutputs {
  appid?: boolean;
  authnSel?: boolean;
  exts?: AuthenticationExtensionsSupported;
  loc?: Coordinates;
  txAuthGeneric?: ArrayBuffer;
  txAuthSimple?: string;
  uvi?: ArrayBuffer;
  uvm?: UvmEntries;
}

export interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  id?: string;
}

export interface PublicKeyCredentialEntity {
  icon?: string;
  name: string;
}

/** The position and altitude of the device on Earth, as well as the accuracy with which these properties are calculated. */
export interface Coordinates {
  readonly accuracy: number;
  readonly altitude: number | null;
  readonly altitudeAccuracy: number | null;
  readonly heading: number | null;
  readonly latitude: number;
  readonly longitude: number;
  readonly speed: number | null;
}

export type AttestationConveyancePreference = 'direct' | 'indirect' | 'none';
export type AuthenticatorTransport = 'ble' | 'internal' | 'nfc' | 'usb';
export type COSEAlgorithmIdentifier = number;
export type UserVerificationRequirement = 'discouraged' | 'preferred' | 'required';
export type AuthenticatorSelectionList = AAGUID[];
export type AuthenticatorAttachment = 'cross-platform' | 'platform';
export type BufferSource = ArrayBufferView | ArrayBuffer;
export type PublicKeyCredentialType = 'public-key';
export type AAGUID = BufferSource;
export type AuthenticationExtensionsSupported = string[];
export type UvmEntries = UvmEntry[];
export type UvmEntry = number[];
