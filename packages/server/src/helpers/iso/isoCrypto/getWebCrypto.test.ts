import { assertEquals, assertThrows } from 'https://deno.land/std@0.198.0/assert/mod.ts';
import { returnsNext, stub } from 'https://deno.land/std@0.198.0/testing/mock.ts';

import { _getWebCryptoInternals, getWebCrypto, MissingWebCrypto } from './getWebCrypto.ts';

Deno.test('should return globalThis.crypto when present', () => {
  // Clear whatever version of crypto might have been set
  _getWebCryptoInternals.setCachedCrypto(undefined);

  // Pretend globalThis.crypto exists
  const newGlobalThisCrypto = {};
  const mockGlobalThisCrypto = stub(
    _getWebCryptoInternals,
    'stubThisGlobalThisCrypto',
    // @ts-ignore: globalThis.crypto
    returnsNext([newGlobalThisCrypto]),
  );

  const returnedCrypto = getWebCrypto();

  assertEquals(returnedCrypto, newGlobalThisCrypto);

  mockGlobalThisCrypto.restore();
});

Deno.test('should raise MissingWebCrypto error when nothing is available', () => {
  // Clear whatever version of crypto might have been set
  _getWebCryptoInternals.setCachedCrypto(undefined);

  // Pretend globalThis.crypto doesn't exist
  const mockGlobalThisCrypto = stub(
    _getWebCryptoInternals,
    'stubThisGlobalThisCrypto',
    // @ts-ignore: globalThis.crypto
    returnsNext([undefined]),
  );

  assertThrows(
    () => getWebCrypto(),
    MissingWebCrypto,
    'Crypto API could not be located',
  );

  mockGlobalThisCrypto.restore();
});
