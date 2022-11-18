import { SubtleCryptoAlg } from './structs';

/**
 * Convert algorithms like "SHA1", "sha256", etc... into values like "SHA-1", "SHA-256", etc...
 * that `.digest()` will accept
 */
export function normalizeSHAAlgorithm(algorithm: string): SubtleCryptoAlg {
  if (/sha\d{1,3}/i.test(algorithm)) {
    algorithm = algorithm.replace(/sha/i, 'SHA-');
  }

  return algorithm.toUpperCase() as SubtleCryptoAlg;
}
