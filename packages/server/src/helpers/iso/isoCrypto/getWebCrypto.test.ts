import { assertEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';
import { returnsNext, stub } from 'https://deno.land/std@0.198.0/testing/mock.ts';

import { _getWebCryptoInternals, getWebCrypto } from './getWebCrypto.ts';

Deno.test('Should return globalThis.crypto when present', async () => {
  // Back up globalThis.crypto
  const originalCrypto = globalThis.crypto;

  // Overwrite globalThis.crypto
  const newCrypto = {};
  Object.defineProperty(globalThis, 'crypto', { value: newCrypto, writable: true });

  const returnedCrypto = await getWebCrypto();

  assertEquals(returnedCrypto, newCrypto);

  // Restore globalThis.crypto
  Object.defineProperty(globalThis, 'crypto', { value: originalCrypto, writable: true });
});

Deno.test('Should return node:crypto.webcrypto when globalThis.crypto is missing', async () => {
  // Mock out just enough of the 'node:crypto' module
  const fakeNodeCrypto = { webcrypto: {} };
  const mockDecodeClientData = stub(
    _getWebCryptoInternals,
    'stubThisImportNodeCrypto',
    // @ts-ignore: Pretending to return something from Node
    returnsNext([fakeNodeCrypto]),
  );

  // Back up globalThis.crypto
  const originalCrypto = globalThis.crypto;

  // Overwrite globalThis.crypto
  const newCrypto = undefined;
  Object.defineProperty(globalThis, 'crypto', { value: newCrypto, writable: true });

  const returnedCrypto = await getWebCrypto();

  assertEquals(returnedCrypto, fakeNodeCrypto.webcrypto);

  // Restore globalThis.crypto
  Object.defineProperty(globalThis, 'crypto', { value: originalCrypto, writable: true });
  mockDecodeClientData.restore();
});

Deno.test(
  'Should return globalThis.crypto when present, while node:crypto is present but missing webcrypto',
  async () => {
    // Mock out just enough of the 'node:crypto' module, but like we're in Node v14
    const fakeNodeCrypto = { webcrypto: undefined };
    const mockDecodeClientData = stub(
      _getWebCryptoInternals,
      'stubThisImportNodeCrypto',
      // @ts-ignore: Pretending to return something from Node
      returnsNext([fakeNodeCrypto]),
    );

    // Back up globalThis.crypto
    const originalCrypto = globalThis.crypto;

    // Overwrite globalThis.crypto
    const fakeGlobalCrypto = {};
    Object.defineProperty(globalThis, 'crypto', { value: fakeGlobalCrypto, writable: true });

    const returnedCrypto = await getWebCrypto();

    assertEquals(returnedCrypto, fakeGlobalCrypto);

    // Restore globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', { value: originalCrypto, writable: true });
    mockDecodeClientData.restore();
  },
);
