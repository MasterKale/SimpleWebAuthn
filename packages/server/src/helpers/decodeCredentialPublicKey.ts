import { COSEPublicKey } from './cose.js';
import { isoCBOR } from './iso/index.js';

export function decodeCredentialPublicKey(publicKey: Uint8Array): COSEPublicKey {
  return isoCBOR.decodeFirst<COSEPublicKey>(publicKey);
}
