import { COSEPublicKey } from './convertCOSEtoPKCS';
import { decodeCborFirst } from './decodeCbor';

export function decodeCredentialPublicKey(publicKey: Buffer): COSEPublicKey {
  return decodeCborFirst(publicKey);
}
