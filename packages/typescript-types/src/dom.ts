export interface txAuthGenericArg {
  content: ArrayBuffer;
  contentType: string;
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

export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  readonly authenticatorData: ArrayBuffer;
  readonly signature: ArrayBuffer;
  readonly userHandle: ArrayBuffer | null;
}

export interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
  readonly attestationObject: ArrayBuffer;
}

export interface AuthenticatorResponse {
  readonly clientDataJSON: ArrayBuffer;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}

export interface Coordinates {
  readonly accuracy: number;
  readonly altitude: number | null;
  readonly altitudeAccuracy: number | null;
  readonly heading: number | null;
  readonly latitude: number;
  readonly longitude: number;
  readonly speed: number | null;
}

export interface Credential {
  readonly id: string;
  readonly type: string;
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

export interface PublicKeyCredentialEntity {
  icon?: string;
  name: string;
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

export interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  id?: string;
}

export interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  displayName: string;
  id: BufferSource;
}

export type AAGUID = BufferSource;
export type AttestationConveyancePreference = 'direct' | 'indirect' | 'none';
export type AuthenticationExtensionsSupported = string[];
export type AuthenticatorAttachment = 'cross-platform' | 'platform';
export type AuthenticatorSelectionList = AAGUID[];
export type AuthenticatorTransport = 'ble' | 'internal' | 'nfc' | 'usb';
export type BufferSource = ArrayBuffer | ArrayBufferView;
export type COSEAlgorithmIdentifier = number;
export type PublicKeyCredentialType = 'public-key';
export type UserVerificationRequirement = 'discouraged' | 'preferred' | 'required';
export type UvmEntry = number[];
export type UvmEntries = UvmEntry[];
