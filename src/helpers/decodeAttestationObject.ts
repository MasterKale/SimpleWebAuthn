import base64url from 'base64url';
import cbor from 'cbor';

import { AttestationObject } from '@types';

/**
 *
 * @param obj
 */
export default function decodeAttestationObject(obj: string): AttestationObject {
  const toBuffer = base64url.toBuffer(obj);
  const toCBOR = cbor.decodeAllSync(toBuffer)[0];
  return toCBOR;
}
