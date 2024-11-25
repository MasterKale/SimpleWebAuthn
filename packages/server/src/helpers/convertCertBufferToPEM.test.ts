import { assert, assertEquals } from '@std/assert';

import { convertCertBufferToPEM } from './convertCertBufferToPEM.ts';

Deno.test('should return pem when input is base64URLString', () => {
  const input =
    'Y2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJpbmcgY2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJpbmcgY2VydEJ1ZmZlclN0cmluZw';
  const actual = convertCertBufferToPEM(input);
  const actualPemArr = actual.split('\n');

  assertEquals(
    actual,
    `-----BEGIN CERTIFICATE-----
Y2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJTdHJp
bmcgY2VydEJ1ZmZlclN0cmluZyBjZXJ0QnVmZmVyU3RyaW5nIGNlcnRCdWZmZXJT
dHJpbmcgY2VydEJ1ZmZlclN0cmluZw==
-----END CERTIFICATE-----
`,
  );

  assertEquals(actualPemArr[0], '-----BEGIN CERTIFICATE-----');
  assert(actualPemArr[1].length <= 64);
  assert(actualPemArr[2].length <= 64);
  assert(actualPemArr[3].length <= 64);
  assertEquals(actualPemArr[4], '-----END CERTIFICATE-----');
});

Deno.test('should return pem when input is buffer', () => {
  const input = new Uint8Array(128).fill(0);
  const actual = convertCertBufferToPEM(input);
  const actualPemArr = actual.split('\n');
  assertEquals(
    actual,
    `-----BEGIN CERTIFICATE-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END CERTIFICATE-----
`,
  );

  assertEquals(actualPemArr[0], '-----BEGIN CERTIFICATE-----');
  assert(actualPemArr[1].length <= 64);
  assert(actualPemArr[2].length <= 64);
  assert(actualPemArr[3].length <= 64);
  assertEquals(actualPemArr[4], '-----END CERTIFICATE-----');
});
