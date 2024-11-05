/// <reference lib="DOM" />
import { assert, assertFalse } from '@std/assert';
import { spy } from '@std/testing/mock';

import { browserSupportsWebAuthnAutofill } from './browserSupportsWebAuthnAutofill.ts';

Deno.test('should return true when conditional mediation is supported', async () => {
  // @ts-ignore: Stubbing out PublicKeyCredential so it exists
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.isConditionalMediationAvailable = spy(async () => true);

  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  assert(supportsAutofill);
});

Deno.test('should return false when conditional mediation is not supported', async () => {
  // @ts-ignore: Stubbing out PublicKeyCredential so it exists
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.isConditionalMediationAvailable = spy(async () => false);

  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  assertFalse(supportsAutofill);
});

Deno.test('should return false when browser does not support WebAuthn', async () => {
  // @ts-ignore: We know what we're doing so it's _fiiiine_
  delete globalThis.PublicKeyCredential;
  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  assertFalse(supportsAutofill);
});
