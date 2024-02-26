import { assert, assertNotEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { generateChallenge } from './generateChallenge.ts';

Deno.test('should return a buffer of at least 32 bytes', () => {
  const challenge = generateChallenge();

  assert(challenge.byteLength >= 32);
});

Deno.test('should return random bytes on each execution', () => {
  const challenge1 = generateChallenge();
  const challenge2 = generateChallenge();

  assertNotEquals(challenge1, challenge2);
});
