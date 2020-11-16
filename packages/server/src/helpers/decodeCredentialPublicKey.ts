import { COSEPublicKey } from './convertCOSEtoPKCS';
import { decodeCborFirst } from './decodeCbor';

export default function decodeCredentialPublicKey(publicKey: Buffer): COSEPublicKey {
  return decodeCborFirst(publicKey);
}
