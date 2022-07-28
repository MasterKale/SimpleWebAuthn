import base64url from "base64url";
import cbor from "cbor";
import { COSEKEYS } from "./convertCOSEtoPKCS";
import { convertPublicKeyToPEM } from "./convertPublicKeyToPEM";

test('should return pem when input is base64URLString', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  const x = Buffer.from("gh9MmXjtmcHFesofqWZ6iuxSdAYgoPVvfJqpv1818lo", "base64")
  const y = Buffer.from("3BDZHsNvKUb5VbyGPqcAFf4FGuPhJ2Xy215oWDw_1jc", "base64")
  mockCOSEKey.set(COSEKEYS.kty, 2);
  mockCOSEKey.set(COSEKEYS.alg, -7);
  mockCOSEKey.set(COSEKEYS.crv, 1);
  mockCOSEKey.set(COSEKEYS.x, x);
  mockCOSEKey.set(COSEKEYS.y, y);

  jest.spyOn(cbor, "decodeAllSync").mockReturnValueOnce([mockCOSEKey]);
  const input = base64url.toBuffer('test');
  const actual = convertPublicKeyToPEM(input);
  expect(actual).toEqual(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgh9MmXjtmcHFesofqWZ6iuxSdAYg\noPVvfJqpv1818lrcENkew28pRvlVvIY+pwAV/gUa4+EnZfLbXmhYPD/WNw==
-----END PUBLIC KEY-----
`);
});


test('should return pem when input is base64URLString', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  const n = Buffer.from("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "base64")
  const e = Buffer.from("AQAB", "base64")
  mockCOSEKey.set(COSEKEYS.kty, 3);
  mockCOSEKey.set(COSEKEYS.alg, -7);
  mockCOSEKey.set(COSEKEYS.crv, 1);
  mockCOSEKey.set(COSEKEYS.n, n);
  mockCOSEKey.set(COSEKEYS.e, e);

  jest.spyOn(cbor, "decodeAllSync").mockReturnValueOnce([mockCOSEKey]);
  const input = base64url.toBuffer('test');
  const actual = convertPublicKeyToPEM(input);
  expect(actual).toEqual(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt
7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----
`);
});

test('should return pem when input is base64URLString', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  mockCOSEKey.set(COSEKEYS.kty, 0);
  mockCOSEKey.set(COSEKEYS.alg, -7);

  jest.spyOn(cbor, "decodeAllSync").mockReturnValueOnce([mockCOSEKey]);
  const input = base64url.toBuffer('test');
  try {
    convertPublicKeyToPEM(input);
  } catch(err) {
    expect((err as Error).message).toEqual("Public key was missing kty");
  }
});

test('should return pem when input is base64URLString', () => {
  const mockCOSEKey = new Map<number, number | Buffer>();

  mockCOSEKey.set(COSEKEYS.kty, 1);
  mockCOSEKey.set(COSEKEYS.alg, -7);

  jest.spyOn(cbor, "decodeAllSync").mockReturnValueOnce([mockCOSEKey]);
  const input = base64url.toBuffer('test');
  try {
    convertPublicKeyToPEM(input);
  } catch(err) {
    expect((err as Error).message).toEqual("Could not convert public key type 1 to PEM");
  }
});
