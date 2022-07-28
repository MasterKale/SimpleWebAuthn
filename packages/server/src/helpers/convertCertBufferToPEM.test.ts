import { convertCertBufferToPEM } from './convertCertBufferToPEM';

test('should return pem when input is base64URLString', () => {
  const input =
    'Y2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJpbmcgY2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJpbmcgY2VydEJ1ZmZlclN0cmluZw';
  const actual = convertCertBufferToPEM(input);
  const actualPemArr = actual.split('\n');

  expect(actual).toEqual(`-----BEGIN CERTIFICATE-----
Y2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJp
bmcgY2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJT
dHJpbmcgY2VydEJ1ZmZlclN0cmluZw==
-----END CERTIFICATE-----
`);

  expect(actualPemArr[0]).toEqual('-----BEGIN CERTIFICATE-----');
  expect(actualPemArr[1].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[2].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[3].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[4]).toEqual('-----END CERTIFICATE-----');
});

test('should return pem when input is buffer', () => {
  const input = Buffer.alloc(128);
  const actual = convertCertBufferToPEM(input);
  const actualPemArr = actual.split('\n');
  expect(actual).toEqual(`-----BEGIN CERTIFICATE-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END CERTIFICATE-----
`);

  expect(actualPemArr[0]).toEqual('-----BEGIN CERTIFICATE-----');
  expect(actualPemArr[1].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[2].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[3].length).toBeLessThanOrEqual(64);
  expect(actualPemArr[4]).toEqual('-----END CERTIFICATE-----');
});
