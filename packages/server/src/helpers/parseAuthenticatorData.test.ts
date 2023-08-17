import { assertEquals } from "https://deno.land/std@0.198.0/assert/mod.ts";

import { parseAuthenticatorData } from "./parseAuthenticatorData.ts";
import { AuthenticationExtensionsAuthenticatorOutputs } from "./decodeAuthenticatorExtensions.ts";
import { isoBase64URL } from "./iso/index.ts";

// Grabbed this from a Conformance test, contains attestation data
const authDataWithAT = isoBase64URL.toBuffer(
  "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAJch83ZdWwUm4niTLNjZU81AAIHa7Ksm5br3hAh3UjxP9+4rqu8BEsD+7SZ2xWe1/yHv6pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=",
  "base64",
);

// Grabbed this from a Conformance test, contains extension data
const authDataWithED = isoBase64URL.toBuffer(
  "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2OBAAAAjaFxZXhhbXBsZS5leHRlbnNpb254dlRoaXMgaXMgYW4gZXhhbXBsZSBleHRlbnNpb24hIElmIHlvdSByZWFkIHRoaXMgbWVzc2FnZSwgeW91IHByb2JhYmx5IHN1Y2Nlc3NmdWxseSBwYXNzaW5nIGNvbmZvcm1hbmNlIHRlc3RzLiBHb29kIGpvYiE=",
  "base64",
);

Deno.test("should parse flags", () => {
  const parsed = parseAuthenticatorData(authDataWithED);

  const { flags } = parsed;

  assertEquals(flags.up, true);
  assertEquals(flags.uv, false);
  assertEquals(flags.be, false);
  assertEquals(flags.bs, false);
  assertEquals(flags.at, false);
  assertEquals(flags.ed, true);
});

Deno.test("should parse attestation data", () => {
  const parsed = parseAuthenticatorData(authDataWithAT);

  const { credentialID, credentialPublicKey, aaguid, counter } = parsed;

  assertEquals(
    isoBase64URL.fromBuffer(credentialID!),
    "drsqybluveECHdSPE_37iuq7wESwP7tJnbFZ7X_Ie_o",
  );
  assertEquals(
    isoBase64URL.fromBuffer(credentialPublicKey!, "base64"),
    "pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=",
  );
  assertEquals(
    isoBase64URL.fromBuffer(aaguid!, "base64"),
    "yHzdl1bBSbieJMs2NlTzUA==",
  );
  assertEquals(
    counter,
    37,
  );
});

Deno.test("should parse extension data", () => {
  const parsed = parseAuthenticatorData(authDataWithED);

  const { extensionsData } = parsed;
  assertEquals(
    extensionsData,
    {
      "example.extension":
        "This is an example extension! If you read this message, you probably successfully passing conformance tests. Good job!",
    } as AuthenticationExtensionsAuthenticatorOutputs,
  );
});
