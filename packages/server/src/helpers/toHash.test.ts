import { assertEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { toHash } from './toHash.ts';

Deno.test('should return a buffer of at 32 bytes for input string', async () => {
  const hash = await toHash('string');
  assertEquals(hash.byteLength, 32);
});

Deno.test('should return a buffer of at 32 bytes for input Buffer', async () => {
  const hash = await toHash(new Uint8Array(10).fill(0));
  assertEquals(hash.byteLength, 32);
});
