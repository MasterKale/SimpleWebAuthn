import { webcrypto } from 'node:crypto';
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from '@peculiar/asn1-schema';

import { COSEALG, COSECRV, COSEKEYS, COSEPublicKeyEC2 } from "../../cose";
import { mapCoseAlgToWebCryptoAlg } from "./mapCoseAlgToWebCryptoAlg";
import { importKey } from './importKey';
import { isoBase64URL, isoUint8Array } from '../index';
import { SubtleCryptoCrv } from "./structs";

/**
 * Verify a signature using an EC2 public key
 */
export async function verifyEC2(opts: {
  cosePublicKey: COSEPublicKeyEC2,
  signature: Uint8Array,
  data: Uint8Array,
  shaHashOverride?: COSEALG,
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

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

  const finalSignature = isoUint8Array.concat([rBytes, sBytes]);

  // Import the public key
  const alg = cosePublicKey.get(COSEKEYS.alg);
  const crv = cosePublicKey.get(COSEKEYS.crv);
  const x = cosePublicKey.get(COSEKEYS.x);
  const y = cosePublicKey.get(COSEKEYS.y);

  if (!alg) {
    throw new Error('Public key was missing alg (EC2)');
  }

  if (!crv) {
    throw new Error('Public key was missing crv (EC2)');
  }

  if (!x) {
    throw new Error('Public key was missing x (EC2)');
  }

  if (!y) {
    throw new Error('Public key was missing y (EC2)');
  }

  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.P256) {
    _crv = 'P-256';
  } else if (crv === COSECRV.P384) {
    _crv = 'P-384';
  } else if (crv === COSECRV.P521) {
    _crv = 'P-521';
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }

  const keyData: JsonWebKey = {
    kty: "EC",
    crv: _crv,
    x: isoBase64URL.fromBuffer(x),
    y: isoBase64URL.fromBuffer(y),
    ext: false,
  };

  const keyAlgorithm: EcKeyImportParams = {
    /**
     * Note to future self: you can't use `mapCoseAlgToWebCryptoKeyAlgName()` here because some
     * leaf certs from actual devices specified an RSA SHA value for `alg` (e.g. `-257`) which
     * would then map here to `'RSASSA-PKCS1-v1_5'`. We always want `'ECDSA'` here so we'll
     * hard-code this.
     */
    name: 'ECDSA',
    namedCurve: _crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  // Determine which SHA algorithm to use for signature verification
  let subtleAlg = mapCoseAlgToWebCryptoAlg(alg);
  if (shaHashOverride) {
    subtleAlg = mapCoseAlgToWebCryptoAlg(shaHashOverride);
  }

  const verifyAlgorithm: EcdsaParams = {
    name: 'ECDSA',
    hash: { name: subtleAlg },
  };

  if (globalThis.crypto) {
    return globalThis.crypto.subtle.verify(verifyAlgorithm, key, finalSignature, data);
  } else {
    return webcrypto.subtle.verify(verifyAlgorithm, key, finalSignature, data);
  }
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
