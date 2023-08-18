import { assert, assertNotEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { generateChallenge } from './generateChallenge.ts';

Deno.test('should return a buffer of at least 32 bytes', async () => {
  const challenge = await generateChallenge();

  assert(challenge.byteLength >= 32);
});

Deno.test('should return random bytes on each execution', async () => {
  const challenge1 = await generateChallenge();
  const challenge2 = await generateChallenge();

  assertNotEquals(challenge1, challenge2);
});
