/// <reference lib="DOM" />
import { assert, assertEquals, assertFalse } from '@std/assert';
import { spy } from '@std/testing/mock';

import { platformAuthenticatorIsAvailable } from './platformAuthenticatorIsAvailable.ts';

Deno.test('should return true when platform authenticator is available', async () => {
  // @ts-ignore: Stubbing out PublicKeyCredential so it exists
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = spy(async () =>
    true
  );

  const isAvailable = await platformAuthenticatorIsAvailable();

  assert(isAvailable);
});

Deno.test('should return false when platform authenticator is unavailable', async () => {
  // @ts-ignore: Stubbing out PublicKeyCredential so it exists
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = spy(async () =>
    false
  );

  const isAvailable = await platformAuthenticatorIsAvailable();

  assertFalse(isAvailable);
});

Deno.test('should return false when browser does not support WebAuthn', async () => {
  // @ts-ignore: We know what we're doing so it's _fiiiine_
  delete globalThis.PublicKeyCredential;
  const isAvailable = await platformAuthenticatorIsAvailable();

  assertFalse(isAvailable);
});
