import { id_ecdsaWithSHA256, id_ecdsaWithSHA384, id_ecdsaWithSHA512 } from '@peculiar/asn1-ecc';
import {
  id_sha1WithRSAEncryption,
  id_sha256WithRSAEncryption,
  id_sha384WithRSAEncryption,
  id_sha512WithRSAEncryption,
} from '@peculiar/asn1-rsa';
import { id_ml_dsa_44, id_ml_dsa_65, id_ml_dsa_87 } from '@peculiar/asn1-x509-post-quantum';
import { COSEALG } from './cose.ts';

/**
 * Map X.509 signature algorithm OIDs to COSE algorithm IDs
 */
export function mapX509SignatureAlgToCOSEAlg(
  signatureAlgorithm: string,
): COSEALG {
  let alg: COSEALG;

  if (signatureAlgorithm === id_ecdsaWithSHA256) {
    alg = COSEALG.ES256;
  } else if (signatureAlgorithm === id_ecdsaWithSHA384) {
    alg = COSEALG.ES384;
  } else if (signatureAlgorithm === id_ecdsaWithSHA512) {
    alg = COSEALG.ES512;
  } else if (signatureAlgorithm === id_sha256WithRSAEncryption) {
    alg = COSEALG.RS256;
  } else if (signatureAlgorithm === id_sha384WithRSAEncryption) {
    alg = COSEALG.RS384;
  } else if (signatureAlgorithm === id_sha512WithRSAEncryption) {
    alg = COSEALG.RS512;
  } else if (signatureAlgorithm === id_sha1WithRSAEncryption) {
    alg = COSEALG.RS1;
  } else if (signatureAlgorithm === id_ml_dsa_44) {
    alg = COSEALG.ML_DSA_44;
  } else if (signatureAlgorithm === id_ml_dsa_65) {
    alg = COSEALG.ML_DSA_65;
  } else if (signatureAlgorithm === id_ml_dsa_87) {
    alg = COSEALG.ML_DSA_87;
  } else {
    throw new Error(
      `Unable to map X.509 signature algorithm ${signatureAlgorithm} to a COSE algorithm`,
    );
  }

  return alg;
}
