import { isoCBOR } from './iso';

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(attestationObject: Uint8Array): AttestationObject {
  return isoCBOR.decodeFirst<AttestationObject>(attestationObject);
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
  get(key: 'fmt'): AttestationFormat;
  get(key: 'attStmt'): AttestationStatement;
  get(key: 'authData'): Uint8Array;
};

/**
 * `AttestationStatement` will be an instance of `Map`, but these keys help make finite the list of
 * possible values within it.
 */
export type AttestationStatement = {
  get(key: 'sig'): Uint8Array | undefined;
  get(key: 'x5c'): Uint8Array[] | undefined;
  get(key: 'response'): Uint8Array | undefined;
  get(key: 'alg'): number | undefined;
  get(key: 'ver'): string | undefined;
  get(key: 'certInfo'): Uint8Array | undefined;
  get(key: 'pubArea'): Uint8Array | undefined;
  // `Map` properties
  get size(): number;
};
