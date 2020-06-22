import cbor from 'cbor';
import type { SigningSchemeHash } from 'node-rsa';

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

export enum COSEKTY {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
}

export const COSERSASCHEME: { [key: string]: SigningSchemeHash } = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512',
};

// See https://w3c.github.io/webauthn/#sctn-alg-identifier
export const COSECRV: { [key: number]: string } = {
  // alg: -7
  1: 'p256',
  // alg: -35
  2: 'p384',
  // alg: -36
  3: 'p521',
  // alg: -8
  6: 'ed25519',
};

export const COSEALGHASH: { [key: string]: string } = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-7': 'sha256',
  '-8': 'sha512',
  '-36': 'sha512',
};
