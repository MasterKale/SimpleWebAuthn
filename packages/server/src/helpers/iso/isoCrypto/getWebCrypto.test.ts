import { assertEquals, assertRejects } from 'https://deno.land/std@0.198.0/assert/mod.ts';
import { returnsNext, stub } from 'https://deno.land/std@0.198.0/testing/mock.ts';

import { _getWebCryptoInternals, getWebCrypto, MissingWebCrypto } from './getWebCrypto.ts';

Deno.test('should return globalThis.crypto when present', async () => {
  // Pretend globalThis.crypto exists
  const newGlobalThisCrypto = {};
  const mockGlobalThisCrypto = stub(
    _getWebCryptoInternals,
    'stubThisGlobalThisCrypto',
    // @ts-ignore: globalThis.crypto
    returnsNext([newGlobalThisCrypto]),
  );

  const returnedCrypto = await getWebCrypto();

  assertEquals(returnedCrypto, newGlobalThisCrypto);

  mockGlobalThisCrypto.restore();
});

Deno.test('should return node:crypto.webcrypto when globalThis.crypto is missing', async () => {
  // Pretend globalThis.crypto doesn't exist
  const mockGlobalThisCrypto = stub(
    _getWebCryptoInternals,
    'stubThisGlobalThisCrypto',
    // @ts-ignore: globalThis.crypto
    returnsNext([undefined]),
  );

  // Mock out just enough of the 'node:crypto' module
  const fakeNodeCrypto = { webcrypto: {} };
  const mockImportNodeCrypto = stub(
    _getWebCryptoInternals,
    'stubThisImportNodeCrypto',
    // @ts-ignore: node:crypto
    returnsNext([fakeNodeCrypto]),
  );

  const returnedCrypto = await getWebCrypto();

  assertEquals(returnedCrypto, fakeNodeCrypto.webcrypto);

  mockGlobalThisCrypto.restore();
  mockImportNodeCrypto.restore();
});

Deno.test(
  'should return globalThis.crypto when present, while node:crypto.webcrypto is present',
  async () => {
    // Pretend globalThis.crypto exists
    const fakeGlobalThisCrypto = {};
    const mockGlobalThisCrypto = stub(
      _getWebCryptoInternals,
      'stubThisGlobalThisCrypto',
      // @ts-ignore: globalThis.crypto
      returnsNext([fakeGlobalThisCrypto]),
    );

    // Mock out just enough of the 'node:crypto' module, but like we're in Node v14
    const fakeNodeCrypto = { webcrypto: {} };
    const mockImportNodeCrypto = stub(
      _getWebCryptoInternals,
      'stubThisImportNodeCrypto',
      // @ts-ignore: node:crypto
      returnsNext([fakeNodeCrypto]),
    );

    const returnedCrypto = await getWebCrypto();

    assertEquals(returnedCrypto, fakeGlobalThisCrypto);

    mockGlobalThisCrypto.restore();
    mockImportNodeCrypto.restore();
  },
);

Deno.test(
  'should return globalThis.crypto when present, while node:crypto is present but missing webcrypto',
  async () => {
    // Pretend globalThis.crypto exists
    const fakeGlobalThisCrypto = {};
    const mockGlobalThisCrypto = stub(
      _getWebCryptoInternals,
      'stubThisGlobalThisCrypto',
      // @ts-ignore: globalThis.crypto
      returnsNext([fakeGlobalThisCrypto]),
    );

    // Mock out just enough of the 'node:crypto' module, but like we're in Node v14
    const fakeNodeCrypto = { webcrypto: undefined };
    const mockImportNodeCrypto = stub(
      _getWebCryptoInternals,
      'stubThisImportNodeCrypto',
      // @ts-ignore: node:crypto
      returnsNext([fakeNodeCrypto]),
    );

    const returnedCrypto = await getWebCrypto();

    assertEquals(returnedCrypto, fakeGlobalThisCrypto);

    mockGlobalThisCrypto.restore();
    mockImportNodeCrypto.restore();
  },
);

Deno.test('should raise MissingWebCrypto error when nothing is available', async () => {
  // Clear whatever version of crypto might have been set
  _getWebCryptoInternals.setCachedCrypto(undefined);

  // Pretend globalThis.crypto doesn't exist
  const mockGlobalThisCrypto = stub(
    _getWebCryptoInternals,
    'stubThisGlobalThisCrypto',
    // @ts-ignore: globalThis.crypto
    returnsNext([undefined]),
  );

  // Pretend node:crypto doesn't exist
  const mockImportNodeCrypto = stub(
    _getWebCryptoInternals,
    'stubThisImportNodeCrypto',
    // @ts-ignore: node:crypto
    returnsNext([undefined]),
  );

  await assertRejects(
    () => getWebCrypto(),
    MissingWebCrypto,
    'Crypto API could not be located',
  );

  mockGlobalThisCrypto.restore();
  mockImportNodeCrypto.restore();
});
