import { COSEPublicKey } from './cose.ts';
import { isoCBOR } from './iso/index.ts';

export function decodeCredentialPublicKey(
  publicKey: Uint8Array,
): COSEPublicKey {
  return _decodeCredentialPublicKeyInternals.stubThis(
    isoCBOR.decodeFirst<COSEPublicKey>(publicKey),
  );
}

// Make it possible to stub the return value during testing
export const _decodeCredentialPublicKeyInternals = {
  stubThis: (value: COSEPublicKey) => value,
};
