import { AsnParser, ECDSASigValue } from '../../../deps.ts';
import { COSECRV } from '../../cose.ts';
import { isoUint8Array } from '../index.ts';

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export function unwrapEC2Signature(signature: Uint8Array, crv: COSECRV): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  const n = getSignatureComponentLength(crv);

  const rBytes = toNormalizedBytes(parsedSignature.r, n);
  const sBytes = toNormalizedBytes(parsedSignature.s, n);

  const finalSignature = isoUint8Array.concat([rBytes, sBytes]);

  return finalSignature;
}

/**
 * ECDSA signatures with in the subtle crypto API expect signatures with `r` and `s` values
 * encoded to a specific length depending on the order of the curve.
 *
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function getSignatureComponentLength(crv: COSECRV): number {
  switch (crv) {
  case COSECRV.P256:
    return 32;
  case COSECRV.P384:
    return 48;
  case COSECRV.P521:
    return 66;
  default:
    throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }
}

/**
 * Converts the ASN.1 integer representation to bytes of a specific length `n`.
 *
 * DER encodes integers as big-endian byte arrays, with as small as possible representation and
 * require leading `0` bytes to disambiguate between negative and positive numbers. This means
 * that `r` and `s` can potentially not be the expected length `n` that is needed by the WebCrypto
 * subtle API: if there it leading `0`s it can be shorter than expected, and if it has a leading
 * `1` bit, it can be one byte longer.
 *
 * See <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function toNormalizedBytes(i: ArrayBuffer, n: number): Uint8Array {
  const iBytes = new Uint8Array(i);

  const normalizedBytes = new Uint8Array(n);
  if (iBytes.length <= n) {
    normalizedBytes.set(iBytes, n - iBytes.length);
  } else if (iBytes.length === n + 1 && iBytes[0] === 0) {
    normalizedBytes.set(iBytes.slice(1));
  } else {
    throw new Error("invalid signature component length");
  }

  return normalizedBytes;
}
