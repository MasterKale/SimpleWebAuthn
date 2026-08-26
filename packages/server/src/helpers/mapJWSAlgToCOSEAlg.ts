import { COSEALG } from './cose.ts';

/**
 * Map JWS algorithms to COSE algorithm IDs
 *
 * See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1 for possible values
 */
export function mapJWSAlgToCOSEAlg(alg: string): COSEALG {
  let algCOSE: COSEALG;

  if (alg === 'ES256') {
    algCOSE = COSEALG.ES256;
  } else if (alg === 'ES384') {
    algCOSE = COSEALG.ES384;
  } else if (alg === 'ES512') {
    algCOSE = COSEALG.ES512;
  } else if (alg === 'RS256') {
    algCOSE = COSEALG.RS256;
  } else if (alg === 'RS384') {
    algCOSE = COSEALG.RS384;
  } else if (alg === 'RS512') {
    algCOSE = COSEALG.RS512;
  } else {
    throw new Error(`Unable to map JWS algorithm "${alg}" to a COSE algorithm`);
  }

  return algCOSE;
}
