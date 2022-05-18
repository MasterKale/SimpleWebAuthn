import cbor from 'cbor';
import { AttestationFormat, AttestationStatement } from '../helpers/decodeAttestationObject';

export default function decodeAttObjForDevicePublicKey(attObjForDevicePublicKey: Buffer): AttObjForDevicePublicKey {
  const toCBOR: AttObjForDevicePublicKey = cbor.decodeAllSync(attObjForDevicePublicKey)[0];
  return toCBOR;
}

export type AttObjForDevicePublicKey = {
  sig: Buffer;
  aaguid: Buffer;
  dpk: Buffer;
  scope: number;
  nonce: Buffer;
  fmt: AttestationFormat;
  attStmt: AttestationStatement;
};
