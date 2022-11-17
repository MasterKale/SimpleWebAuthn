import { webcrypto } from 'node:crypto';
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from '@peculiar/asn1-schema';

import { isoUint8Array, isoBase64URL } from './index';
import { COSECRV, COSEKEYS, COSEKTY, COSEALG, COSEPublicKeyEC2, COSEPublicKeyRSA, isCOSEAlg, isCOSEPublicKeyEC2, isCOSEPublicKeyRSA } from '../convertCOSEtoPKCS';

/**
 * Fill up the provided bytes array with random bytes equal to its length.
 *
 * @returns the same bytes array passed into the method
 */
export function getRandomValues(array: Uint8Array): Uint8Array {
  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    globalThis.crypto.getRandomValues(array);
  } else {
    // We're in Node, use Node's Crypto
    webcrypto.getRandomValues(array);
  }

  return array;
}

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm Must be one of the following values:
 * - `"SHA-1"`
 * - `"SHA-256"`
 * - `"SHA-384"`
 * - `"SHA-512"`
 */
export async function digest(data: Uint8Array, algorithm: string): Promise<Uint8Array> {
  algorithm = normalizeSHAAlgorithm(algorithm);

  let hashed: ArrayBuffer
  if (globalThis.crypto) {
    // We're in a browser-like runtime, use global Crypto
    hashed = await globalThis.crypto.subtle.digest(algorithm, data);
  } else {
    // We're in Node, use Node's Crypto
    hashed = await webcrypto.subtle.digest(algorithm, data);
  }

  return new Uint8Array(hashed);
}

/**
 * Verify signatures with their public key. Supports EC2 and RSA public keys.
 */
export async function verify({
  publicKey,
  coseKty,
  coseAlg,
  signature,
  data,
}: {
  publicKey: CryptoKey,
  coseKty: COSEKTY,
  coseAlg: COSEALG,
  signature: Uint8Array,
  data: Uint8Array,
}): Promise<boolean> {
  if (coseKty === COSEKTY.EC2) {
    // The signature is wrapped in ASN.1 structure, so we need to peel it apart
    const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }

    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }

    const signatureBytes = isoUint8Array.concat([rBytes, sBytes]);

    return verifyECSignature(publicKey, signatureBytes, data, coseAlg);
  } else if (coseKty === COSEKTY.RSA) {
    return verifyRSASignature(publicKey, signature, data);
  }

  throw new Error(
    `Signature verification with public key of kty ${coseKty} is not supported by this method`,
  );
}

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
 * Verify a signature using an EC2 public key
 */
async function verifyECSignature(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  alg: COSEALG,
): Promise<boolean> {
  const subtleAlg = mapCoseAlgToWebCryptoAlg(alg);

  const algorithm: EcdsaParams = {
    name: 'ECDSA',
    hash: { name: subtleAlg },
  };
  if (globalThis.crypto) {
    return globalThis.crypto.subtle.verify(algorithm, key, signature, data);
  } else {
    return webcrypto.subtle.verify(algorithm, key, signature, data);
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

async function verifyRSASignature(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const algorithm = {
    name: 'RSASSA-PKCS1-v1_5',
  };
  if (globalThis.crypto) {
    return globalThis.crypto.subtle.verify(algorithm, key, signature, data);
  } else {
    return webcrypto.subtle.verify(algorithm, key, signature, data);
  }
}

/**
 * Convert algorithms like "SHA1", "sha256", etc... into values like "SHA-1", "SHA-256", etc...
 * that `.digest()` will accept
 */
function normalizeSHAAlgorithm(algorithm: string): SubtleCryptoAlg {
  if (/sha\d{1,3}/i.test(algorithm)) {
    algorithm = algorithm.replace(/sha/i, 'SHA-');
  }

  return algorithm.toUpperCase() as SubtleCryptoAlg;
}

/**
 * Determine if the DER-specific `00` byte at the start of an ECDSA signature byte sequence
 * should be removed based on the following logic:
 *
 * "If the leading byte is 0x0, and the the high order bit on the second byte is not set to 0,
 * then remove the leading 0x0 byte"
 */
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return (bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0);
}

type SubtleCryptoCrv = "P-256" | "P-384" | "P-521";

/**
 * Convert a COSE alg ID into a corresponding string value that WebCrypto APIs expect
 */
function mapCoseAlgToWebCryptoAlg(alg: COSEALG): SubtleCryptoAlg {
  if ([-65535].indexOf(alg) >= 0) {
    return 'SHA-1';
  } else if ([-7, -37, -257].indexOf(alg) >= 0) {
    return 'SHA-256';
  } else if ([-35, -38, -258].indexOf(alg) >= 0) {
    return 'SHA-384'
  } else if ([-8, -36, -39, -259].indexOf(alg) >= 0) {
    return 'SHA-512';
  }

  throw new Error(`Unexpected COSE alg value of ${alg}`);
}
export type SubtleCryptoAlg = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
