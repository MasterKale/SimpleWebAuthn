import { isoCBOR, isoUint8Array } from './iso';

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 */
export function convertCOSEtoPKCS(cosePublicKey: Uint8Array): Uint8Array {
  // This is a little sloppy, I'm using COSEPublicKeyEC2 since it could have both x and y, but when
  // there's no y it means it's probably better typed as COSEPublicKeyOKP. I'll leave this for now
  // and revisit it later if it ever becomes an actual problem.
  const struct = isoCBOR.decodeFirst<COSEPublicKeyEC2>(cosePublicKey);

  const tag = Uint8Array.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error('COSE public key was missing x');
  }

  if (y) {
    return isoUint8Array.concat([tag, x, y]);
  }

  return isoUint8Array.concat([tag, x]);
}

/**
 * Fundamental values that are needed to discern the more specific COSE public key types below
 */
export type COSEPublicKey = {
  // Getters
  get(key: COSEKEYS.kty): COSEKTY | undefined;
  get(key: COSEKEYS.alg): COSEALG | undefined;
  // Setters
  set(key: COSEKEYS.kty, value: COSEKTY): void;
  set(key: COSEKEYS.alg, value: COSEALG): void;
};

export type COSEPublicKeyOKP = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.x): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.x, value: Uint8Array): void;
};

export type COSEPublicKeyEC2 = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.crv): number | undefined;
  get(key: COSEKEYS.x): Uint8Array | undefined;
  get(key: COSEKEYS.y): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.crv, value: number): void;
  set(key: COSEKEYS.x, value: Uint8Array): void;
  set(key: COSEKEYS.y, value: Uint8Array): void;
};

export type COSEPublicKeyRSA = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.n): Uint8Array | undefined;
  get(key: COSEKEYS.e): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.n, value: Uint8Array): void;
  set(key: COSEKEYS.e, value: Uint8Array): void;
};

export function isCOSEPublicKeyOKP(publicKey: COSEPublicKey): publicKey is COSEPublicKeyOKP {
  return publicKey.get(COSEKEYS.kty) === COSEKTY.OKP;
}

export function isCOSEPublicKeyEC2(publicKey: COSEPublicKey): publicKey is COSEPublicKeyEC2 {
  return publicKey.get(COSEKEYS.kty) === COSEKTY.EC2;
}

export function isCOSEPublicKeyRSA(publicKey: COSEPublicKey): publicKey is COSEPublicKeyRSA {
  return publicKey.get(COSEKEYS.kty) === COSEKTY.RSA;
}

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

export enum COSECRV {
  P256 = 1,
  P384 = 2,
  P521 = 3,
  ED25519 = 6,
}

export const coseAlgs = [-65535, -259, -258, -257, -47, -39, -38, -37, -36, -35, -8, -7] as const;
export type COSEALG = typeof coseAlgs[number];
/**
 * Ensure that a number is a valid COSE algorithm ID
 */
export function isCOSEAlg(alg: number): alg is COSEALG {
  return coseAlgs.indexOf(alg as COSEALG) >= 0;
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
export const coseCRV: { [key: number]: string } = {
  // alg: -7
  1: 'p256',
  // alg: -35
  2: 'p384',
  // alg: -36
  3: 'p521',
  // alg: -8
  6: 'ed25519',
};

export const coseAlgSHAHashMap: { [K in COSEALG]: string } = {
  '-65535': 'sha1',
  '-259': 'sha512',
  '-258': 'sha384',
  '-257': 'sha256',
  '-47': 'sha256',
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
