/// <reference lib="DOM" />
import { assert } from '@std/assert';

import * as index from './index.ts';

Deno.test('should export method `startRegistration`', () => {
  assert(index.startRegistration);
});

Deno.test('should export method `startAuthentication`', () => {
  assert(index.startAuthentication);
});

Deno.test('should export method `browserSupportsWebAuthn`', () => {
  assert(index.browserSupportsWebAuthn);
});

Deno.test('should export method `browserSupportsWebAuthnAutofill`', () => {
  assert(index.browserSupportsWebAuthnAutofill);
});

Deno.test('should export method `platformAuthenticatorIsAvailable`', () => {
  assert(index.platformAuthenticatorIsAvailable);
});

Deno.test('should export method `base64URLStringToBuffer`', () => {
  assert(index.base64URLStringToBuffer);
});

Deno.test('should export method `bufferToBase64URLString`', () => {
  assert(index.bufferToBase64URLString);
});

Deno.test('should export singleton `WebAuthnAbortService`', () => {
  assert(index.WebAuthnAbortService);
});
