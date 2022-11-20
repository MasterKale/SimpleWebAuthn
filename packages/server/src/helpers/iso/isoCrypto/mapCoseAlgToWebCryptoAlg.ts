import { SubtleCryptoAlg } from "./structs";
import { COSEALG } from "../../cose";


/**
 * Convert a COSE alg ID into a corresponding string value that WebCrypto APIs expect
 */
export function mapCoseAlgToWebCryptoAlg(alg: COSEALG): SubtleCryptoAlg {
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
