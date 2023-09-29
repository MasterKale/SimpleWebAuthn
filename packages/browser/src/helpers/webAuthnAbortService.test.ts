import { WebauthnAbortService } from './webAuthnAbortService';

test('should create a new abort signal every time', () => {
  const signal1 = WebauthnAbortService.createNewAbortSignal();
  const signal2 = WebauthnAbortService.createNewAbortSignal();

  expect(signal2).not.toBe(signal1);
});

test('should call abort() with AbortError on existing controller when creating a new signal', () => {
  // Populate `.controller`
  WebauthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = jest.fn();
  // @ts-ignore: Ignore the fact that `controller` is private
  WebauthnAbortService.controller.abort = abortSpy;

  // Generate a new signal, which should call `abort()` on the existing controller
  WebauthnAbortService.createNewAbortSignal();
  expect(abortSpy).toHaveBeenCalledTimes(1);

  // Make sure we raise an AbortError so it can be detected correctly
  const abortReason = abortSpy.mock.calls[0][0];
  expect(abortReason).toBeInstanceOf(Error);
  expect(abortReason.name).toEqual('AbortError');
});
