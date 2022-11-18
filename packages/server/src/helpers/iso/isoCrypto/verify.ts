import { webcrypto } from 'node:crypto';

import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from '@peculiar/asn1-schema';

import { COSEALG, COSEKTY } from '../../convertCOSEtoPKCS';
import { isoUint8Array } from '../index';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg';

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
 *
 */
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
