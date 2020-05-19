/**
 * An object that can be passed into navigator.credentials.create(...) in the browser
 */
export type AttestationCredentials = {
  publicKey: PublicKeyCredentialCreationOptions,
};

/**
 * An object that can be passed into navigator.credentials.get(...) in the browser
 */
export type AssertionCredentials = {
  publicKey: PublicKeyCredentialRequestOptions,
};

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface EncodedAuthenticatorAttestationResponse extends Omit<
AuthenticatorAttestationResponse, 'clientDataJSON' | 'attestationObject'
> {
  base64ClientDataJSON: string,
  base64AttestationObject: string;
}

export enum ATTESTATION_FORMATS {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  NONE = 'none',
};

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

export type VerifiedAttestation = {
  verified: boolean,
  authenticatorInfo?: {
    fmt: ATTESTATION_FORMATS,
    counter: number,
    base64PublicKey: string,
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
};

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

