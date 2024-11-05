import { WebAuthnAbortService } from './webAuthnAbortService.ts';

test('should create a new abort signal every time', () => {
  const signal1 = WebAuthnAbortService.createNewAbortSignal();
  const signal2 = WebAuthnAbortService.createNewAbortSignal();

  expect(signal2).not.toBe(signal1);
});

test('should call abort() with AbortError on existing controller when creating a new signal', () => {
  // Populate `.controller`
  WebAuthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = jest.fn();
  // @ts-ignore: Ignore the fact that `controller` is private
  WebAuthnAbortService.controller.abort = abortSpy;

  // Generate a new signal, which should call `abort()` on the existing controller
  WebAuthnAbortService.createNewAbortSignal();
  expect(abortSpy).toHaveBeenCalledTimes(1);

  // Make sure we raise an AbortError so it can be detected correctly
  const abortReason = abortSpy.mock.calls[0][0];
  expect(abortReason).toBeInstanceOf(Error);
  expect(abortReason.name).toEqual('AbortError');
});

test('should cancel active WebAuthn ceremony when manually cancelled', () => {
  // Populate `.controller`
  WebAuthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = jest.fn();
  // @ts-ignore: Ignore the fact that `controller` is private
  WebAuthnAbortService.controller.abort = abortSpy;

  // Cancel the in-flight ceremony, which should call `abort()` on the existing controller
  WebAuthnAbortService.cancelCeremony();
  expect(abortSpy).toHaveBeenCalledTimes(1);

  // Make sure we raise an AbortError so it can be detected correctly
  const abortReason = abortSpy.mock.calls[0][0];
  expect(abortReason).toBeInstanceOf(Error);
  expect(abortReason.name).toEqual('AbortError');

  // Ensure that we don't set up a new AbortController because it's unnecessary to do so
  // @ts-ignore: Ignore the fact that `controller` is private
  expect(WebAuthnAbortService.controller).toBeUndefined();
});
