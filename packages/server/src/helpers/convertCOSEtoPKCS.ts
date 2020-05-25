import cbor from 'cbor';
import { COSEKEYS, COSEPublicKey } from '@webauthntine/typescript-types';

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 *
 * @param cosePublicKey COSE-encoded public key
 * @return RAW PKCS encoded public key
 */
export default function convertCOSEtoPKCS(cosePublicKey: Buffer) {
  /*
    +------+-------+-------+---------+----------------------------------+
    | name | key   | label | type    | description                      |
    |      | type  |       |         |                                  |
    +------+-------+-------+---------+----------------------------------+
    | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
    |      |       |       | tstr    | the COSE Curves registry         |
    |      |       |       |         |                                  |
    | x    | 2     | -2    | bstr    | X Coordinate                     |
    |      |       |       |         |                                  |
    | y    | 2     | -3    | bstr /  | Y Coordinate                     |
    |      |       |       | bool    |                                  |
    |      |       |       |         |                                  |
    | d    | 2     | -4    | bstr    | Private key                      |
    +------+-------+-------+---------+----------------------------------+
  */
  const struct: COSEPublicKey = cbor.decodeFirstSync(cosePublicKey);

  const tag = Buffer.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error('COSE public key was missing x');
  }

  if (!y) {
    throw new Error('COSE public key was missing y');
  }

  return Buffer.concat([tag, (x as Buffer), (y as Buffer)]);
}
