import cbor from 'cbor';

import { COSEPublicKey } from './convertCOSEtoPKCS';

export default function decodeCredentialPublicKey(publicKey: Buffer): COSEPublicKey {
  return cbor.decodeFirstSync(publicKey);
}
