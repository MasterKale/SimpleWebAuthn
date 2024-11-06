import { assertEquals, assertInstanceOf, assertNotEquals } from '@std/assert';
import { assertSpyCalls, spy } from '@std/testing/mock';

import { WebAuthnAbortService } from './webAuthnAbortService.ts';

Deno.test('should create a new abort signal every time', () => {
  const signal1 = WebAuthnAbortService.createNewAbortSignal();
  const signal2 = WebAuthnAbortService.createNewAbortSignal();

  assertNotEquals(signal2, signal1);
});

Deno.test('should call abort() with AbortError on existing controller when creating a new signal', () => {
  // Populate `.controller`
  WebAuthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = spy();
  // @ts-ignore: Ignore the fact that `controller` is private
  WebAuthnAbortService.controller.abort = abortSpy;

  // Generate a new signal, which should call `abort()` on the existing controller
  WebAuthnAbortService.createNewAbortSignal();
  assertSpyCalls(abortSpy, 1);

  // Make sure we raise an AbortError so it can be detected correctly
  const abortReason = abortSpy.calls.at(0)?.args[0];
  assertInstanceOf(abortReason, Error);
  assertEquals(abortReason.name, 'AbortError');
});

Deno.test('should cancel active WebAuthn ceremony when manually cancelled', () => {
  // Populate `.controller`
  WebAuthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = spy();
  // @ts-ignore: Ignore the fact that `controller` is private
  WebAuthnAbortService.controller.abort = abortSpy;

  // Cancel the in-flight ceremony, which should call `abort()` on the existing controller
  WebAuthnAbortService.cancelCeremony();
  assertSpyCalls(abortSpy, 1);

  // Make sure we raise an AbortError so it can be detected correctly
  const abortReason = abortSpy.calls.at(0)?.args[0];
  assertInstanceOf(abortReason, Error);
  assertEquals(abortReason.name, 'AbortError');

  // Ensure that we don't set up a new AbortController because it's unnecessary to do so
  // @ts-ignore: Ignore the fact that `controller` is private
  assertEquals(WebAuthnAbortService.controller, undefined);
});
