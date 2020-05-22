/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.create(...) in the browser.
 *
 * Noteworthy values:
 * @param challenge A random string of characters. Will be converted to a Uint8Array in the browser
 * @param user.id Your unique, internal ID for the user. Will be converted to a Uint8Array in the
 * browser
 */
export type PublicKeyCredentialCreationOptionsJSON = {
  publicKey: {
    challenge: string,
    // The organization registering and authenticating the user
    rp: {
      name: string,
      id: string,
    },
    user: {
      id: string,
      name: string,
      displayName: string,
    },
    pubKeyCredParams: [{
      alg: -7,
      type: 'public-key',
    }],
    timeout?: number,
    attestation: 'direct' | 'indirect',
  },
};

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 *
 * Noteworthy values:
 * @param challenge A random string of characters. Will be converted to a Uint8Array in the browser
 * @param allowCredentials.id Base64-encoded credentialId. Will be converted to a Uint8Array in the
 * browser
 */
export type PublicKeyCredentialRequestOptionsJSON = {
  publicKey: {
    //
    challenge: string,
    allowCredentials: {
      // Will be converted to a Uint8Array in the browser
      id: string,
      type: 'public-key',
      transports?: AuthenticatorTransport[],
    }[],
    // extensions?: AuthenticationExtensionsClientInputs,
    rpId?: string,
    timeout?: number,
    userVerification?: UserVerificationRequirement,
  },
};

/**
 * The value returned from navigator.credentials.create()
 */
export interface AttestationCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AssertionCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAttestationResponseJSON extends Omit<
AuthenticatorAttestationResponse, 'clientDataJSON' | 'attestationObject'
> {
  base64ClientDataJSON: string,
  base64AttestationObject: string;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAssertionResponseJSON extends Omit<
AuthenticatorAssertionResponse, 'clientDataJSON' | 'authenticatorData' | 'signature' | 'userHandle'
> {
  base64AuthenticatorData: string;
  base64ClientDataJSON: string;
  base64Signature: string;
  base64UserHandle?: string;
}

export enum ATTESTATION_FORMATS {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  NONE = 'none',
}

export type AttestationObject = {
  fmt: ATTESTATION_FORMATS,
  attStmt: {
    sig?: Buffer,
    x5c?: Buffer[],
    ecdaaKeyId?: Buffer,
    response?: Buffer,
  },
  authData: Buffer,
};

export type ParsedAttestationAuthData = {
  rpIdHash: Buffer,
  flagsBuf: Buffer,
  flags: {
      up: boolean,
      uv: boolean,
      at: boolean,
      ed: boolean,
      flagsInt: number,
  },
  counter: number,
  counterBuf: Buffer,
  aaguid?: Buffer,
  credentialID?: Buffer,
  COSEPublicKey?: Buffer,
};

export type ClientDataJSON = {
  type: string,
  challenge: string,
  origin: string,
};

/**
 * Result of attestation verification
 */
export type VerifiedAttestation = {
  verified: boolean,
  userVerified: boolean;
  authenticatorInfo?: {
    fmt: ATTESTATION_FORMATS,
    counter: number,
    base64PublicKey: string,
    base64CredentialID: string,
  },
};

/**
 * Result of assertion verification
 */
export type VerifiedAssertion = {
  verified: boolean;
  counter: number;
};

export type CertificateInfo = {
  subject: { [key: string]: string },
  version: number,
  basicConstraintsCA: boolean,
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
  alg: 'string',
  x5c: string[],
};

export type SafetyNetJWTPayload = {
  nonce: string,
  timestampMs: number,
  apkPackageName: string,
  apkDigestSha256: string,
  ctsProfileMatch: boolean,
  apkCertificateDigestSha256: string[],
  basicIntegrity: boolean,
};

export type SafetyNetJWTSignature = string;

export type ParsedAssertionAuthData = {
  rpIdHash: Buffer,
  flagsBuf: Buffer,
  flags: number,
  counter: number,
  counterBuf: Buffer,
};

/**
 * U2F Presence constant
 */
export const U2F_USER_PRESENTED = 0x01;

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  base64PublicKey: string,
  base64CredentialID: string,
  // Number of times this device is expected to have been used
  counter: number,
};
