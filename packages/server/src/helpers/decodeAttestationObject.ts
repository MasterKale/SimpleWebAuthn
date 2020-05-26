import base64url from 'base64url';
import cbor from 'cbor';
import { AttestationObject } from '@simplewebauthn/typescript-types';

/**
 * Convert an AttestationObject from base64 string to a proper object
 *
 * @param base64AttestationObject Base64-encoded Attestation Object
 */
export default function decodeAttestationObject(
  base64AttestationObject: string,
): AttestationObject {
  const toBuffer = base64url.toBuffer(base64AttestationObject);
  const toCBOR: AttestationObject = cbor.decodeAllSync(toBuffer)[0];
  return toCBOR;
}
