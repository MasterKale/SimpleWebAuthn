import { COSEPublicKey } from './convertCOSEtoPKCS';
import * as isoCBOR from './isoCBOR';

export function decodeCredentialPublicKey(publicKey: Uint8Array): COSEPublicKey {
  return cbor.decodeFirst<COSEPublicKey>(publicKey);
}
