import { COSEPublicKey } from './convertCOSEtoPKCS';
import { decodeCborFirst } from './decodeCbor';

export function decodeCredentialPublicKey(publicKey: Uint8Array): COSEPublicKey {
  return decodeCborFirst(publicKey);
}
