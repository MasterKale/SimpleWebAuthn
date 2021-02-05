import base64url from 'base64url';
import cbor from 'cbor';

/**
 * Convert an AttestationObject from base64url string to a proper object
 *
 * @param base64AttestationObject Base64URL-encoded Attestation Object
 */
export default function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
  const toCBOR: AttestationObject = cbor.decodeAllSync(attestationObject)[0];
  return toCBOR;
}

export enum ATTESTATION_FORMAT {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  ANDROID_KEY = 'android-key',
  TPM = 'tpm',
  APPLE = 'apple',
  NONE = 'none',
}

export type AttestationObject = {
  fmt: ATTESTATION_FORMAT;
  attStmt: AttestationStatement;
  authData: Buffer;
};

export type AttestationStatement = {
  sig?: Buffer;
  x5c?: Buffer[];
  response?: Buffer;
  alg?: number;
  ver?: string;
  certInfo?: Buffer;
  pubArea?: Buffer;
};
