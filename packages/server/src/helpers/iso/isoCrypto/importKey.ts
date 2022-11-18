import { webcrypto } from 'node:crypto';

import { SubtleCryptoCrv } from './structs';
import { normalizeSHAAlgorithm } from './normalizeSHAAlgorithm';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg';
import {
  COSECRV,
  COSEKEYS,
  COSEKTY,
  COSEALG,
  COSEPublicKeyEC2,
  COSEPublicKeyRSA,
  isCOSEAlg,
  isCOSEPublicKeyEC2,
  isCOSEPublicKeyRSA,
} from '../../convertCOSEtoPKCS';
import { isoBase64URL } from '../index';

/**
 * Import an EC2 or RSA public key from its COSE representation
 *
 * @param publicKey A `Map` containing COSE-specific public key properties
 * @param rsaHashAlgorithm A SHA hashing identifier for use when verifying signatures with the
 * returned RSA public key (e.g. `"sha1"`, `"sha256"`, etc...), if applicable
 */
export async function importKey(publicKey: COSEPublicKeyEC2 | COSEPublicKeyRSA, rsaHashAlgorithm?: string): Promise<CryptoKey> {
  const kty = publicKey.get(COSEKEYS.kty);

  if (!kty) {
    throw new Error('Public key was missing kty');
  }

  if (isCOSEPublicKeyEC2(publicKey)) {
    return importECKey(publicKey);
  }

  if (isCOSEPublicKeyRSA(publicKey)) {
    return importRSAKey(publicKey, rsaHashAlgorithm);
  }

  throw new Error(`Unable to import public key of kty ${kty}`);
}

/**
 * Import an EC2 public key from its COSE representation
 */
 async function importECKey(publicKey: COSEPublicKeyEC2): Promise<CryptoKey> {
  const crv = publicKey.get(COSEKEYS.crv);
  const x = publicKey.get(COSEKEYS.x);
  const y = publicKey.get(COSEKEYS.y);

  if (!crv) {
    throw new Error('EC2 public key was missing crv');
  }

  if (!x) {
    throw new Error('EC2 public key was missing x');
  }

  if (!y) {
    throw new Error('EC2 public key was missing y');
  }

  /**
   * Convert a COSE crv ID into a corresponding string value that WebCrypto APIs expect
   */
  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.P256) {
    _crv = 'P-256';
  } else if (crv === COSECRV.P384) {
    _crv = 'P-384';
  } else if (crv === COSECRV.P521) {
    _crv = 'P-521';
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv}`);
  }

  const jwk: JsonWebKey = {
    kty: "EC",
    crv: _crv,
    x: isoBase64URL.fromBuffer(x),
    y: isoBase64URL.fromBuffer(y),
    ext: false,
  };

  const algorithm: EcKeyImportParams = {
    name: 'ECDSA',
    namedCurve: _crv,
  };

  const extractable = false;

  const keyUsages: KeyUsage[] = ["verify"];

  if (globalThis.crypto) {
    return globalThis.crypto.subtle.importKey('jwk', jwk, algorithm, extractable, keyUsages);
  } else {
    return webcrypto.subtle.importKey('jwk', jwk, algorithm, extractable, keyUsages);
  }
}

/**
 * Import an RSA public key from its COSE representation
 */
 async function importRSAKey(publicKey: COSEPublicKeyRSA, hashAlgorithm?: string): Promise<CryptoKey> {
  const alg = publicKey.get(COSEKEYS.alg);
  const n = publicKey.get(COSEKEYS.n);
  const e = publicKey.get(COSEKEYS.e);

  if (!alg) {
    throw new Error('Public key was missing alg (RSA)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (RSA)`);
  }

  if (!n) {
    throw new Error('Public key was missing n (RSA)');
  }

  if (!e) {
    throw new Error('Public key was missing e (RSA)');
  }

  const jwk: JsonWebKey = {
    kty: 'RSA',
    alg: '',
    n: isoBase64URL.fromBuffer(n),
    e: isoBase64URL.fromBuffer(e),
    ext: false,
  };

  const keyAlgorithm = {
    name: 'RSASSA-PKCS1-v1_5',
    // This is actually the digest hash that'll get used by `.verify()`
    hash: { name: mapCoseAlgToWebCryptoAlg(alg) },
  };

  if (hashAlgorithm) {
    const normalized = normalizeSHAAlgorithm(hashAlgorithm);
    keyAlgorithm.hash.name = normalized;
  }

  if (keyAlgorithm.hash.name === 'SHA-256') {
    jwk.alg = 'RS256';
  } else if (keyAlgorithm.hash.name === 'SHA-384') {
    jwk.alg = 'RS384';
  } else if (keyAlgorithm.hash.name === 'SHA-512') {
    jwk.alg = 'RS512';
  } else if (keyAlgorithm.hash.name === 'SHA-1') {
    jwk.alg = 'RS1';
  }

  const extractable = false;

  const keyUsages: KeyUsage[] = ["verify"];

  if (globalThis.crypto) {
    return globalThis.crypto.subtle.importKey('jwk', jwk, keyAlgorithm, extractable, keyUsages);
  } else {
    return webcrypto.subtle.importKey('jwk', jwk, keyAlgorithm, extractable, keyUsages);
  }
}
