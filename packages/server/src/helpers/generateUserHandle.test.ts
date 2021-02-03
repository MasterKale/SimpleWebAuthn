import generateUserHandle from './generateUserHandle';

test('should return a buffer of 64 bytes', () => {
  const userHandle = generateUserHandle();

  expect(userHandle.byteLength).toBe(64);
});

test('should return random bytes on each execution', () => {
  const challenge1 = generateUserHandle();
  const challenge2 = generateUserHandle();

  expect(challenge1).not.toEqual(challenge2);
});
