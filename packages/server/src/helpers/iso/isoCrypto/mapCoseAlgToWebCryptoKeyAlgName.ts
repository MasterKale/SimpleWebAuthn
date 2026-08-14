import { COSEALG } from '../../cose.ts';
import type { SubtleCryptoKeyAlgName } from './structs.ts';

/**
 * Convert a COSE alg ID into a corresponding key algorithm string value that WebCrypto APIs expect
 *
 * Unless otherwise specified, mappings were referenced from
 * https://w3c.github.io/webcrypto/#jwk-mapping-alg
 */
export function mapCoseAlgToWebCryptoKeyAlgName(
  alg: COSEALG,
): SubtleCryptoKeyAlgName {
  if ([COSEALG.EdDSA].indexOf(alg) >= 0) {
    return 'Ed25519';
  } else if ([COSEALG.ES256, COSEALG.ES384, COSEALG.ES512, COSEALG.ES256K].indexOf(alg) >= 0) {
    return 'ECDSA';
  } else if ([COSEALG.RS256, COSEALG.RS384, COSEALG.RS512, COSEALG.RS1].indexOf(alg) >= 0) {
    return 'RSASSA-PKCS1-v1_5';
  } else if ([COSEALG.PS256, COSEALG.PS384, COSEALG.PS512].indexOf(alg) >= 0) {
    return 'RSA-PSS';
  } else if ([COSEALG.ML_DSA_44].indexOf(alg) >= 0) {
    // https://wicg.github.io/webcrypto-modern-algos/#ml-dsa-registration
    return 'ML-DSA-44';
  } else if ([COSEALG.ML_DSA_65].indexOf(alg) >= 0) {
    // https://wicg.github.io/webcrypto-modern-algos/#ml-dsa-registration
    return 'ML-DSA-65';
  } else if ([COSEALG.ML_DSA_87].indexOf(alg) >= 0) {
    // https://wicg.github.io/webcrypto-modern-algos/#ml-dsa-registration
    return 'ML-DSA-87';
  }

  throw new Error(
    `Could not map COSE alg value of ${alg} to a WebCrypto key alg name`,
  );
}
