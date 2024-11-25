import { assert, assertNotEquals } from '@std/assert';

import { generateUserID } from './generateUserID.ts';

Deno.test('should return a buffer of 32 bytes', async () => {
  const userID = await generateUserID();

  assert(userID.byteLength === 32);
});

Deno.test('should return random bytes on each execution', async () => {
  const userID1 = await generateUserID();
  const userID2 = await generateUserID();

  assertNotEquals(userID1, userID2);
});
