import {
  COSEALG,
  COSEKEYS,
  COSEPublicKey,
  isCOSEPublicKeyEC2,
  isCOSEPublicKeyOKP,
  isCOSEPublicKeyRSA,
} from '../../cose';
import { verifyEC2 } from './verifyEC2';
import { verifyRSA } from './verifyRSA';
import { verifyOKP } from './verifyOKP';

/**
 * Verify signatures with their public key. Supports EC2 and RSA public keys.
 */
export async function verify(opts: {
  cosePublicKey: COSEPublicKey;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  if (isCOSEPublicKeyEC2(cosePublicKey)) {
    return verifyEC2({ cosePublicKey, signature, data, shaHashOverride });
  } else if (isCOSEPublicKeyRSA(cosePublicKey)) {
    return verifyRSA({ cosePublicKey, signature, data, shaHashOverride });
  } else if (isCOSEPublicKeyOKP(cosePublicKey)) {
    return verifyOKP({ cosePublicKey, signature, data });
  }

  const kty = cosePublicKey.get(COSEKEYS.kty);
  throw new Error(
    `Signature verification with public key of kty ${kty} is not supported by this method`,
  );
}
