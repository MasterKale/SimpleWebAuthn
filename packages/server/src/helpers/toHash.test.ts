import { toHash } from './toHash';

test('should return a buffer of at 32 bytes for input string', async () => {
  const hash = await toHash('string');
  expect(hash.byteLength).toEqual(32);
});

test('should return a buffer of at 32 bytes for input Buffer', async () => {
  const hash = await toHash(Buffer.alloc(10));
  expect(hash.byteLength).toEqual(32);
});
