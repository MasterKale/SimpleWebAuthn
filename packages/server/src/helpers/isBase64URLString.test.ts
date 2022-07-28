import { isBase64URLString } from './isBase64URLString';

test('should return true when input is base64URLString', () => {
  const actual = isBase64URLString('U2ltcGxlV2ViQXV0aG4');
  expect(actual).toEqual(true);
});

test('should return false when input is not base64URLString', () => {
  const actual = isBase64URLString('U2ltcGxlV2ViQXV0aG4+');
  expect(actual).toEqual(false);
});

test('should return false when input is blank', () => {
  const actual = isBase64URLString('');
  expect(actual).toEqual(false);
});
