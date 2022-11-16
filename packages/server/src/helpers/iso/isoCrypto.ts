import { webcrypto } from 'node:crypto';
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from '@peculiar/asn1-schema';

import { isoUint8Array, isoBase64URL } from './index';
import { COSECRV, coseCRV, COSEKEYS, COSEKTY, COSEPublicKey } from '../convertCOSEtoPKCS';

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
  algorithm = normalizeAlgorithm(algorithm);

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
 * Verify signatures with their public key. Supports EC2 and RSA public key.
 */
export async function verify(
  publicKey: COSEPublicKey,
  signature: Uint8Array,
  signatureBase: Uint8Array,
): Promise<boolean> {
  const kty = publicKey.get(COSEKEYS.kty);

  if (!kty) {
    throw new Error('Public key was missing kty');
  }

  if (kty === COSEKTY.EC2) {
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

    const alg = publicKey.get(COSEKEYS.alg);
    const crv = publicKey.get(COSEKEYS.crv);
    const x = publicKey.get(COSEKEYS.x);
    const y = publicKey.get(COSEKEYS.y);

    if (!alg) {
      throw new Error('Public key was missing alg');
    }

    if (!crv) {
      throw new Error('Public key was missing crv');
    }

    if (!x) {
      throw new Error('Public key was missing x');
    }

    if (!y) {
      throw new Error('Public key was missing y');
    }

    const subtleCrv = mapCoseCrvToWebCryptoCrv(crv as number);
    const subtleAlg = mapCoseAlgToWebCryptoAlg(alg as number);

    const subtlePublicKey = await importECKey(
      subtleCrv,
      x as Uint8Array,
      y as Uint8Array,
    );

    return verifyECSignature(subtlePublicKey, signatureBytes, signatureBase, subtleAlg);
  }

  return false;
}

/**
 * Import a public key from its corresponding
 */
function importECKey(crv: SubtleCryptoCrv, x: Uint8Array, y: Uint8Array): Promise<CryptoKey> {
  const jwk = {
    kty: "EC",
    crv,
    x: isoBase64URL.fromBuffer(x as Uint8Array),
    y: isoBase64URL.fromBuffer(y as Uint8Array),
    ext: false,
  };

  const algorithm: EcKeyImportParams = {
    name: 'ECDSA',
    namedCurve: crv,
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
 *
 */
function verifyECSignature(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  alg: SubtleCryptoAlg = 'SHA-256',
): Promise<boolean> {
  const algorithm: EcdsaParams = {
    name: 'ECDSA',
    hash: { name: alg },
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
function normalizeAlgorithm(algorithm: string): SubtleCryptoAlg {
  if (/sha\d{1,3}/i.test(algorithm)) {
    algorithm = algorithm.toUpperCase().replace('SHA', 'SHA-');
  }

  return algorithm as SubtleCryptoAlg;
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

/**
 * Convert a COSE crv ID into a corresponding string value that WebCrypto APIs expect
 */
function mapCoseCrvToWebCryptoCrv(crv: number): SubtleCryptoCrv {
  if (crv === COSECRV.P256) {
    return 'P-256';
  }

  if (crv === COSECRV.P384) {
    return 'P-384';
  }

  if (crv === COSECRV.P521) {
    return 'P-521';
  }

  throw new Error(`Unexpected COSE crv value of ${crv}`);
}
type SubtleCryptoCrv = "P-256" | "P-384" | "P-521";

/**
 * Convert a COSE alg ID into a corresponding string value that WebCrypto APIs expect
 */
function mapCoseAlgToWebCryptoAlg(alg: number): SubtleCryptoAlg {
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
