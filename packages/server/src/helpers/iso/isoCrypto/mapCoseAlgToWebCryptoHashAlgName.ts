import type { SubtleCryptoAlg } from './structs.ts';
import { COSEALG } from '../../cose.ts';

/**
 * Convert a COSE alg ID into a corresponding hash algorithm string value that WebCrypto APIs expect
 *
 * Unless otherwise specified, mappings were referenced from
 * https://w3c.github.io/webcrypto/#jwk-mapping-alg
 */
export function mapCoseAlgToWebCryptoHashAlgName(alg: COSEALG): SubtleCryptoAlg {
  if ([COSEALG.RS1].indexOf(alg) >= 0) {
    return 'SHA-1';
  } else if ([COSEALG.ES256, COSEALG.PS256, COSEALG.RS256].indexOf(alg) >= 0) {
    return 'SHA-256';
  } else if ([COSEALG.ES384, COSEALG.PS384, COSEALG.RS384].indexOf(alg) >= 0) {
    return 'SHA-384';
  } else if (
    [COSEALG.ES512, COSEALG.PS512, COSEALG.RS512, COSEALG.EdDSA].indexOf(alg) >=
      0
  ) {
    return 'SHA-512';
  }

  throw new Error(`Could not map COSE alg value of ${alg} to a WebCrypto hash alg name`);
}
