/// <reference lib="DOM" />
import { assert, assertFalse, assertEquals } from '@std/assert';

import { browserSupportsWebAuthn } from './browserSupportsWebAuthn.ts';

Deno.test('should return true when browser supports WebAuthn', () => {
  // @ts-ignore: Stubbing out PublicKeyCredential so it exists
  globalThis.PublicKeyCredential = () => {};
  assert(browserSupportsWebAuthn())
});

Deno.test('should return false when browser does not support WebAuthn', () => {
  // This looks weird but it appeases the linter so it's _fiiiine_
  delete (globalThis as { PublicKeyCredential: unknown }).PublicKeyCredential;
  assertFalse(browserSupportsWebAuthn())
});

Deno.test('should return false when window is undefined', () => {
  // Make window undefined as it is in node environments.
  // @ts-ignore: Intentionally making globalThis unavailable
  globalThis = undefined;

  assertEquals(globalThis, undefined);
  assertFalse(browserSupportsWebAuthn())
});
