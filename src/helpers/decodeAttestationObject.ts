import base64url from 'base64url';
import cbor from 'cbor';

import { ATTESTATION_FORMATS } from './constants';

type AttestationObject = {
  fmt: ATTESTATION_FORMATS,
  attStmt: {
    sig?: Buffer,
    x5c?: Buffer,
  },
  authData: Buffer,
};

/**
 *
 * @param obj
 */
export default function decodeAttestationObject(obj: string): AttestationObject {
  const toBuffer = base64url.toBuffer(obj);
  const toCBOR = cbor.decodeAllSync(toBuffer)[0];
  return toCBOR;
}
