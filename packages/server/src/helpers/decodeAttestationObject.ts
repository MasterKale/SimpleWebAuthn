import { decodeCborFirst } from './decodeCbor';

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
  const toCBOR: AttestationObject = decodeCborFirst(attestationObject);
  return toCBOR;
}

export type AttestationFormat =
  | 'fido-u2f'
  | 'packed'
  | 'android-safetynet'
  | 'android-key'
  | 'tpm'
  | 'apple'
  | 'none';

export type AttestationObject = {
  fmt: AttestationFormat;
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
