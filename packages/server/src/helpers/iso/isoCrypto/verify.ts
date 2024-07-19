import {
  COSEALG,
  COSEKEYS,
  COSEPublicKey,
  isCOSECrv,
  isCOSEPublicKeyEC2,
  isCOSEPublicKeyOKP,
  isCOSEPublicKeyRSA,
} from '../../cose.ts';
import { verifyEC2 } from './verifyEC2.ts';
import { verifyRSA } from './verifyRSA.ts';
import { verifyOKP } from './verifyOKP.ts';
import { unwrapEC2Signature } from './unwrapEC2Signature.ts';

/**
 * Verify signatures with their public key. Supports EC2 and RSA public keys.
 */
export function verify(opts: {
  cosePublicKey: COSEPublicKey;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  if (isCOSEPublicKeyEC2(cosePublicKey)) {
    const crv = cosePublicKey.get(COSEKEYS.crv);
    if (!isCOSECrv(crv)) {
      throw new Error(`unknown COSE curve ${crv}`);
    }
    const unwrappedSignature = unwrapEC2Signature(signature, crv);
    return verifyEC2({
      cosePublicKey,
      signature: unwrappedSignature,
      data,
      shaHashOverride,
    });
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
