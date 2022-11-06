import { COSEAlgorithmIdentifier } from '@simplewebauthn/typescript-types';
import { decodeCborFirst } from './decodeCbor';
import uint8Array from './uint8array';

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 */
export function convertCOSEtoPKCS(cosePublicKey: Uint8Array): Uint8Array {
  const struct: COSEPublicKey = decodeCborFirst(cosePublicKey);

  const tag = Uint8Array.from([0x04]);
  const x = struct[COSEKEYS.x];
  const y = struct[COSEKEYS.y];

  if (!x) {
    throw new Error('COSE public key was missing x');
  }

  if (y) {
    return uint8Array.concat([tag, x as Uint8Array, y as Uint8Array]);
  }

  return uint8Array.concat([tag, x as Uint8Array]);
}

export type COSEPublicKey = { [key: COSEAlgorithmIdentifier]: number | Uint8Array};

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
  '-65535': 'sha1',
  '-259': 'sha512',
  '-258': 'sha384',
  '-257': 'sha256',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-36': 'sha512',
  '-35': 'sha384',
  '-8': 'sha512',
  '-7': 'sha256',
};

/**
 * Imported from node-rsa's types
 */
type SigningSchemeHash =
  | 'pkcs1-ripemd160'
  | 'pkcs1-md4'
  | 'pkcs1-md5'
  | 'pkcs1-sha'
  | 'pkcs1-sha1'
  | 'pkcs1-sha224'
  | 'pkcs1-sha256'
  | 'pkcs1-sha384'
  | 'pkcs1-sha512'
  | 'pss-ripemd160'
  | 'pss-md4'
  | 'pss-md5'
  | 'pss-sha'
  | 'pss-sha1'
  | 'pss-sha224'
  | 'pss-sha256'
  | 'pss-sha384'
  | 'pss-sha512';
