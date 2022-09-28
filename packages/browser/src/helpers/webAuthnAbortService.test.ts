import { webauthnAbortService } from './webAuthnAbortService';

test('should create a new abort signal every time', () => {
  const signal1 = webauthnAbortService.createNewAbortSignal();
  const signal2 = webauthnAbortService.createNewAbortSignal();

  expect(signal2).not.toBe(signal1);
});

test('should call abort() on existing controller when creating a new signal', () => {
  // Populate `.controller`
  webauthnAbortService.createNewAbortSignal();

  // Spy on the existing instance of AbortController
  const abortSpy = jest.fn();
  // @ts-ignore
  webauthnAbortService.controller?.abort = abortSpy;

  // Generate a new signal, which should call `abort()` on the existing controller
  webauthnAbortService.createNewAbortSignal();
  expect(abortSpy).toHaveBeenCalledTimes(1);
});
