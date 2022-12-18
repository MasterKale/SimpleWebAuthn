import { convertX509PublicKeyToCOSE } from '../helpers/convertX509PublicKeyToCOSE';
import { isoBase64URL, isoUint8Array } from '../helpers/iso';
import { COSEALG, COSEKEYS, isCOSEPublicKeyEC2 } from '../helpers/cose';
import { verifyEC2 } from '../helpers/iso/isoCrypto/verifyEC2';

/**
 * Lightweight verification for FIDO MDS JWTs.
 *
 * Currently assumes `"alg": "ES256"` in the JWT header, it's what FIDO MDS uses. If this ever
 * needs to support more JWS algorithms, here's the list of them:
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * (Pulled from https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1)
 */
export async function verifyJWT(jwt: string, leafCert: Uint8Array): Promise<boolean> {
  const [header, payload, signature] = jwt.split('.');

  const certCOSE = convertX509PublicKeyToCOSE(leafCert);

  if (isCOSEPublicKeyEC2(certCOSE)) {
    return verifyEC2({
      data: isoUint8Array.fromUTF8String(`${header}.${payload}`),
      signature: isoBase64URL.toBuffer(signature),
      cosePublicKey: certCOSE,
      shaHashOverride: COSEALG.ES256,
    });
  }

  const kty = certCOSE.get(COSEKEYS.kty);
  throw new Error(
    `JWT verification with public key of kty ${kty} is not supported by this method`,
  );
}
