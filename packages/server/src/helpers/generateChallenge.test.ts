import { generateChallenge } from './generateChallenge';

test('should return a buffer of at least 32 bytes', () => {
  const challenge = generateChallenge();

  expect(challenge.byteLength).toBeGreaterThanOrEqual(32);
});

test('should return random bytes on each execution', () => {
  const challenge1 = generateChallenge();
  const challenge2 = generateChallenge();

  expect(challenge1).not.toEqual(challenge2);
});
