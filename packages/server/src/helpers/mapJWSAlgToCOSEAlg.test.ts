import { assertEquals, assertThrows } from '@std/assert';
import { mapJWSAlgToCOSEAlg } from './mapJWSAlgToCOSEAlg.ts';
import { COSEALG } from './cose.ts';

Deno.test('should map "ES256" to -7', () => {
  assertEquals(mapJWSAlgToCOSEAlg('ES256'), COSEALG.ES256);
});

Deno.test('should map "ES384" to -35', () => {
  assertEquals(mapJWSAlgToCOSEAlg('ES384'), COSEALG.ES384);
});

Deno.test('should map "ES512" to -36', () => {
  assertEquals(mapJWSAlgToCOSEAlg('ES512'), COSEALG.ES512);
});

Deno.test('should map "RS256" to -257', () => {
  assertEquals(mapJWSAlgToCOSEAlg('RS256'), COSEALG.RS256);
});

Deno.test('should map "RS384" to -7', () => {
  assertEquals(mapJWSAlgToCOSEAlg('RS384'), COSEALG.RS384);
});

Deno.test('should map "RS512" to -7', () => {
  assertEquals(mapJWSAlgToCOSEAlg('RS512'), COSEALG.RS512);
});

Deno.test('should raise on unsupported JWS alg', () => {
  assertThrows(() => {
    mapJWSAlgToCOSEAlg('FOOALG');
  });
});
