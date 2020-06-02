import toBase64String from './toBase64String';

import toUint8Array from './toUint8Array';

test('should convert a Buffer to a string with a length that is a multiple of 4', () => {
  const base64 = toBase64String(Buffer.from('123456', 'ascii'));

  expect(base64.length % 4).toEqual(0);
});

test('should convert a Uint8Array to a string with a length that is a multiple of 4', () => {
  const base64 = toBase64String(toUint8Array('123456'));

  expect(base64.length % 4).toEqual(0);
});
