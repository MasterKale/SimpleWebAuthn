import { COSEPublicKey } from './convertCOSEtoPKCS';
import * as cbor from './cbor';

export function decodeCredentialPublicKey(publicKey: Uint8Array): COSEPublicKey {
  return cbor.decodeFirst<COSEPublicKey>(publicKey);
}
