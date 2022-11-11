import { COSEKEYS } from './convertCOSEtoPKCS';
import { convertPublicKeyToPEM } from './convertPublicKeyToPEM';
import * as cbor from './cbor';
import * as uint8Array from './uint8Array';

test('should return pem - EC2', () => {
  const mockEC2Key = new Map<number, number | Uint8Array>();

  const x = uint8Array.fromHex('821f4c9978ed99c1c57aca1fa9667a8aec52740620a0f56f7c9aa9bf5f35f25a');
  const y = uint8Array.fromHex('dc10d91ec36f2946f955bc863ea70015fe051ae3e12765f2db5e68583c3fd637');
  mockEC2Key.set(COSEKEYS.kty, 2);
  mockEC2Key.set(COSEKEYS.alg, -7);
  mockEC2Key.set(COSEKEYS.crv, 1);
  mockEC2Key.set(COSEKEYS.x, x);
  mockEC2Key.set(COSEKEYS.y, y);

  const pubKeyCBOR = cbor.encode(mockEC2Key);

  const actual = convertPublicKeyToPEM(pubKeyCBOR);
  expect(actual).toEqual(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgh9MmXjtmcHFesofqWZ6iuxSdAYg\noPVvfJqpv1818lrcENkew28pRvlVvIY+pwAV/gUa4+EnZfLbXmhYPD/WNw==
-----END PUBLIC KEY-----
`);
});

test('should return pem - RSA', () => {
  const mockRSAKey = new Map<number, number | Buffer>();

  const n = Buffer.from(
    '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    'base64',
  );
  const e = Buffer.from('AQAB', 'base64');
  mockRSAKey.set(COSEKEYS.kty, 3);
  mockRSAKey.set(COSEKEYS.alg, -7);
  mockRSAKey.set(COSEKEYS.crv, 1);
  mockRSAKey.set(COSEKEYS.n, n);
  mockRSAKey.set(COSEKEYS.e, e);

  const pubKeyCBOR = cbor.encode(mockRSAKey);

  const actual = convertPublicKeyToPEM(pubKeyCBOR);
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

  const pubKeyCBOR = cbor.encode(mockCOSEKey);

  try {
    convertPublicKeyToPEM(pubKeyCBOR);
  } catch (err) {
    expect((err as Error).message).toEqual('Public key was missing kty');
  }
});

test('should raise error when kty is OKP (1)', () => {
  const mockOKPKey = new Map<number, number | Buffer>();

  mockOKPKey.set(COSEKEYS.kty, 1);
  mockOKPKey.set(COSEKEYS.alg, -7);

  const pubKeyCBOR = cbor.encode(mockOKPKey);

  try {
    convertPublicKeyToPEM(pubKeyCBOR);
  } catch (err) {
    expect((err as Error).message).toEqual('Could not convert public key type 1 to PEM');
  }
});
