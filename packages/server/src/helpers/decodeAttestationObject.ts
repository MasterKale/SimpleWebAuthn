import cbor from 'cbor';
import { AttestationFormat, AttestationStatement } from '@simplewebauthn/typescript-types';

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
  const toCBOR: AttestationObject = cbor.decodeAllSync(attestationObject)[0];
  return toCBOR;
}

export type AttestationObject = {
  fmt: AttestationFormat;
  attStmt: AttestationStatement;
  authData: Buffer;
};
