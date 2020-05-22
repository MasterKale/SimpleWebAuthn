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
  base64CredentialID: string;
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

export type ParsedAuthenticatorData = {
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
    counter: number,
    base64CredentialID: string,
  },
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

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  base64PublicKey: string,
  base64CredentialID: string,
  // Number of times this device is expected to have been used
  counter: number,
};
