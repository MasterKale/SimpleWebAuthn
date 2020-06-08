import cbor from 'cbor';

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 *
 * @param cosePublicKey COSE-encoded public key
 * @return RAW PKCS encoded public key
 */
export default function convertCOSEtoPKCS(cosePublicKey: Buffer): Buffer {
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

  if (y) {
    return Buffer.concat([tag, x as Buffer, y as Buffer]);
  }

  return Buffer.concat([tag, x as Buffer]);
}

export type COSEPublicKey = Map<COSEAlgorithmIdentifier, number | Buffer>;

export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}
