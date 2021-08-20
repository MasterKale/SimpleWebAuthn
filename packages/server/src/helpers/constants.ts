type COSEInfo = {
  kty: number;
  alg: number;
  crv?: number;
};

/**
 * A mapping of ALG_SIGN hex values (as unsigned shorts) to COSE curve values. Keys should appear as
 * values in a metadata statement's `authenticationAlgorithm` property.
 *
 * From https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html
 * FIDO Registry of Predefined Values - 3.6.1 Authentication Algorithms
 */
export const FIDO_METADATA_AUTH_ALG_TO_COSE: { [algKey: number]: COSEInfo } = {
  // ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
  1: { kty: 2, alg: -7, crv: 1 },
  // ALG_SIGN_RSASSA_PSS_SHA256_RAW
  3: { kty: 3, alg: -37 },
  // ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW
  5: { kty: 2, alg: -7, crv: 8 },
  // ALG_SIGN_RSASSA_PSS_SHA384_RAW
  10: { kty: 3, alg: -38 },
  // ALG_SIGN_RSASSA_PSS_SHA512_RAW
  11: { kty: 3, alg: -39 },
  // ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW
  12: { kty: 3, alg: -257 },
  // ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW
  13: { kty: 3, alg: -258 },
  // ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW
  14: { kty: 3, alg: -259 },
  // ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW
  15: { kty: 3, alg: -65535 },
  // ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW
  16: { kty: 2, alg: -35, crv: 2 },
  // ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW
  17: { kty: 2, alg: -36, crv: 3 },
  // ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW
  18: { kty: 1, alg: -8, crv: 6 },
};
