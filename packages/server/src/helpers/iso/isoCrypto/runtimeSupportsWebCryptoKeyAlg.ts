import type { AlgorithmIdentifier, SubtleCryptoFuture } from '../../../types/index.ts';

/**
 * Use SubtleCrypto.supports() to understand if the runtime supports using the given key algorithm
 * for signature verification.
 */
export function runtimeSupportsWebCryptoKeyAlg(alg: AlgorithmIdentifier): boolean {
  const globalSubtleCrypto = globalThis.SubtleCrypto as unknown as SubtleCryptoFuture;

  if (typeof globalSubtleCrypto.supports !== 'function') {
    return false;
  }

  try {
    return globalSubtleCrypto.supports('verify', alg);
  } catch (_err) {
    return false;
  }
}
