import { browserSupportsWebAuthn } from './browserSupportsWebAuthn';

beforeEach(() => {
  // @ts-ignore 2741
  window.PublicKeyCredential = jest.fn().mockReturnValue(() => {});
});

test('should return true when browser supports WebAuthn', () => {
  expect(browserSupportsWebAuthn()).toBe(true);
});

test('should return false when browser does not support WebAuthn', () => {
  delete (window as any).PublicKeyCredential;
  expect(browserSupportsWebAuthn()).toBe(false);
});

test('should return false when window is undefined', () => {
  // Make window undefined as it is in node environments.
  const windowSpy = jest.spyOn<any, 'window'>(global, 'window', 'get');
  windowSpy.mockImplementation(() => undefined);

  expect(window).toBe(undefined);
  expect(browserSupportsWebAuthn()).toBe(false);

  // Restore original window value.
  windowSpy.mockRestore();
});
