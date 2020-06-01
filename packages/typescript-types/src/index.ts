/**
 * @packageDocumentation
 * @module @simplewebauthn/typescript-types
 * @preferred
 */
/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.create(...) in the browser.
 */
export interface PublicKeyCredentialCreationOptionsJSON extends Omit<
PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'
> {
  // Will be converted to a Uint8Array in the browser
  user: PublicKeyCredentialUserEntityJSON;
  challenge: string;
  excludeCredentials: PublicKeyCredentialDescriptorJSON[];
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON extends Omit<
PublicKeyCredentialRequestOptions, 'challenge' |'allowCredentials'
> {
  // Will be converted to a Uint8Array in the browser
  challenge: string;
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
}

export interface PublicKeyCredentialDescriptorJSON extends Omit<
PublicKeyCredentialDescriptor, 'id'
> {
  // Should be a Base64-encoded credential ID. Will be converted to a Uint8Array in the browser
  id: string;
}

export interface PublicKeyCredentialUserEntityJSON extends Omit <
PublicKeyCredentialUserEntity, 'id'
> {
  // Should be a Base64-encoded credential ID. Will be converted to a Uint8Array in the browser
  id: string;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface AttestationCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
}

export interface AttestationCredentialJSON
  extends Omit<AttestationCredential, 'response' | 'rawId'> {
  rawId: string;
  response: AuthenticatorAttestationResponseJSON;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AssertionCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
}

export interface AssertionCredentialJSON extends Omit<AssertionCredential, 'response' | 'rawId'> {
  rawId: string;
  response: AuthenticatorAssertionResponseJSON;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAttestationResponseJSON
  extends Omit<AuthenticatorAttestationResponse, 'clientDataJSON' | 'attestationObject'> {
  clientDataJSON: string;
  attestationObject: string;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAssertionResponseJSON
  extends Omit<
    AuthenticatorAssertionResponse,
    'authenticatorData' | 'clientDataJSON' | 'signature' | 'userHandle'
  > {
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle?: string;
}

export enum ATTESTATION_FORMATS {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  NONE = 'none',
}

export type AttestationObject = {
  fmt: ATTESTATION_FORMATS;
  attStmt: {
    sig?: Buffer;
    x5c?: Buffer[];
    response?: Buffer;
  };
  authData: Buffer;
};

export type ParsedAuthenticatorData = {
  rpIdHash: Buffer;
  flagsBuf: Buffer;
  flags: {
    up: boolean;
    uv: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Buffer;
  aaguid?: Buffer;
  credentialID?: Buffer;
  COSEPublicKey?: Buffer;
};

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
};

/**
 * Result of attestation verification
 *
 * @param verified If the assertion response could be verified
 * @param userVerified Whether the user was uniquely identified during attestation
 * @param authenticatorInfo.fmt Type of attestation
 * @param authenticatorInfo.counter The number of times the authenticator reported it has been used.
 * Should be kept in a DB for later reference to help prevent replay attacks
 * @param authenticatorInfo.base64PublicKey Base64-encoded ArrayBuffer containing the
 * authenticator's public key. **Should be kept in a DB for later reference!**
 * @param authenticatorInfo.base64CredentialID Base64-encoded ArrayBuffer containing the
 * authenticator's credential ID for the public key above. **Should be kept in a DB for later
 * reference!**
 */
export type VerifiedAttestation = {
  verified: boolean;
  userVerified: boolean;
  authenticatorInfo?: {
    fmt: ATTESTATION_FORMATS;
    counter: number;
    base64PublicKey: string;
    base64CredentialID: string;
  };
};

/**
 * Result of assertion verification
 *
 * @param verified If the assertion response could be verified
 * @param authenticatorInfo.base64CredentialID The ID of the authenticator used during assertion.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticatorInfo.counter The number of times the authenticator identified above reported
 * it has been used. **Should be kept in a DB for later reference to help prevent replay attacks!**
 */
export type VerifiedAssertion = {
  verified: boolean;
  authenticatorInfo: {
    counter: number;
    base64CredentialID: string;
  };
};

export type CertificateInfo = {
  subject: { [key: string]: string };
  version: number;
  basicConstraintsCA: boolean;
};

export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}

export type COSEPublicKey = Map<COSEAlgorithmIdentifier, number | Buffer>;

export type SafetyNetJWTHeader = {
  alg: 'string';
  x5c: string[];
};

export type SafetyNetJWTPayload = {
  nonce: string;
  timestampMs: number;
  apkPackageName: string;
  apkDigestSha256: string;
  ctsProfileMatch: boolean;
  apkCertificateDigestSha256: string[];
  basicIntegrity: boolean;
};

export type SafetyNetJWTSignature = string;

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  base64PublicKey: string;
  base64CredentialID: string;
  // Number of times this device is expected to have been used
  counter: number;
};
