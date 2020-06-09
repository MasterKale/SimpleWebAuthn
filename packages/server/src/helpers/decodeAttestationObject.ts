import base64url from 'base64url';
import cbor from 'cbor';

/**
 * Convert an AttestationObject from base64url string to a proper object
 *
 * @param base64AttestationObject Base64URL-encoded Attestation Object
 */
export default function decodeAttestationObject(
  base64AttestationObject: string,
): AttestationObject {
  const toBuffer = base64url.toBuffer(base64AttestationObject);
  const toCBOR: AttestationObject = cbor.decodeAllSync(toBuffer)[0];
  return toCBOR;
}

export enum ATTESTATION_FORMATS {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  NONE = 'none',
}

export type AttestationObject = {
  fmt: ATTESTATION_FORMATS;
  attStmt: AttestationStatement;
  authData: Buffer;
};

export type AttestationStatement = {
  sig?: Buffer;
  x5c?: Buffer[];
  response?: Buffer;
  alg?: number;
  ver?: string;
};
