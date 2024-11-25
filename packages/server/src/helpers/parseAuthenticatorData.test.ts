import { assertEquals } from '@std/assert';

import { parseAuthenticatorData } from './parseAuthenticatorData.ts';
import { AuthenticationExtensionsAuthenticatorOutputs } from './decodeAuthenticatorExtensions.ts';
import { isoBase64URL, isoUint8Array } from './iso/index.ts';

// Grabbed this from a Conformance test, contains attestation data
const authDataWithAT = isoBase64URL.toBuffer(
  'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAJch83ZdWwUm4niTLNjZU81AAIHa7Ksm5br3hAh3UjxP9+4rqu8BEsD+7SZ2xWe1/yHv6pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=',
  'base64',
);

// Grabbed this from a Conformance test, contains extension data
const authDataWithED = isoBase64URL.toBuffer(
  'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2OBAAAAjaFxZXhhbXBsZS5leHRlbnNpb254dlRoaXMgaXMgYW4gZXhhbXBsZSBleHRlbnNpb24hIElmIHlvdSByZWFkIHRoaXMgbWVzc2FnZSwgeW91IHByb2JhYmx5IHN1Y2Nlc3NmdWxseSBwYXNzaW5nIGNvbmZvcm1hbmNlIHRlc3RzLiBHb29kIGpvYiE=',
  'base64',
);

Deno.test('should parse flags', () => {
  const parsed = parseAuthenticatorData(authDataWithED);

  const { flags } = parsed;

  assertEquals(flags.up, true);
  assertEquals(flags.uv, false);
  assertEquals(flags.be, false);
  assertEquals(flags.bs, false);
  assertEquals(flags.at, false);
  assertEquals(flags.ed, true);
});

Deno.test('should parse attestation data', () => {
  const parsed = parseAuthenticatorData(authDataWithAT);

  const { credentialID, credentialPublicKey, aaguid, counter } = parsed;

  assertEquals(
    isoBase64URL.fromBuffer(credentialID!),
    'drsqybluveECHdSPE_37iuq7wESwP7tJnbFZ7X_Ie_o',
  );
  assertEquals(
    isoBase64URL.fromBuffer(credentialPublicKey!, 'base64'),
    'pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=',
  );
  assertEquals(
    isoBase64URL.fromBuffer(aaguid!, 'base64'),
    'yHzdl1bBSbieJMs2NlTzUA==',
  );
  assertEquals(
    counter,
    37,
  );
});

Deno.test('should parse extension data', () => {
  const parsed = parseAuthenticatorData(authDataWithED);

  const { extensionsData } = parsed;
  assertEquals(
    extensionsData,
    {
      'example.extension':
        'This is an example extension! If you read this message, you probably successfully passing conformance tests. Good job!',
    } as AuthenticationExtensionsAuthenticatorOutputs,
  );
});

Deno.test('should parse malformed authenticator data from Firefox 117', () => {
  /**
   * Firefox 117 is incorrectly serializing authenticator data, and using string values for kty and
   * crv at the same time. See the following issues for more context (I've dealt with this issue
   * before, over in the py_webauthn project):
   *
   * - https://github.com/duo-labs/py_webauthn/issues/175
   * - https://github.com/mozilla/authenticator-rs/pull/292
   */
  const authDataBadKtyHex =
    'b40499b0271a68957267de4ec40056a74c8758c6582e1e01fcf357d73101e7ba450000000400000000000000000000000000000000008072d3a1a3fa7cf32f44367df847585ff0850c7bd62c338ab45be1fda6fdb79982f96c20efc0bb6ed9347e8c1e77690e67b225b485a098f6f46fde3f2a85acd0177a04d6bb5c7566fb89881dfe48ea7abc361f7acaf86a5966adef557930fa5c045c636f50cf938e508a81b845134eb2988dc3af0ab6f98cfc615532684b4a6363a301634f4b50032720674564323535313921982018d51858187318e6188918eb18ab187e18fd18fd185d184b08184b187318e818e118f818c71518ff18f5183a18fd18a3186b185f1109183e183b14';
  const authData = isoUint8Array.fromHex(authDataBadKtyHex);

  const parsed = parseAuthenticatorData(authData);

  const authDataAfterHex = isoUint8Array.toHex(authData);

  // If we can assert this then it means we could parse the bad auth data above
  assertEquals(parsed.flags.at, true);
  // Let's make sure we didn't fundamentally change authData as it would break signature
  // verification if we did.
  assertEquals(authDataBadKtyHex, authDataAfterHex);
});
