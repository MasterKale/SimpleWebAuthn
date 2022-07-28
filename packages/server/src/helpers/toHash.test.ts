import { toHash } from './toHash';

test('should return a buffer of at 32 bytes for input string', () => {
  const hash = toHash('string');
  expect(hash.byteLength).toEqual(32);
});

test('should return a buffer of at 32 bytes for input Buffer', () => {
  const hash = toHash(Buffer.alloc(10));
  expect(hash.byteLength).toEqual(32);
});
