// Silence some console output
// jest.spyOn(console, 'log').mockImplementation();
// jest.spyOn(console, 'debug').mockImplementation();
// jest.spyOn(console, 'error').mockImplementation();

/**
 * JSDom doesn't seem to support `credentials`, so let's define them here so we can mock their
 * implementations in specific tests.
 */
Object.defineProperty(window.navigator, 'credentials', {
  writable: true,
  value: {
    create: jest.fn(),
    get: jest.fn(),
  },
});

/**
 * Allow for setting values to `window.location.hostname`
 */
Object.defineProperty(window, 'location', {
  writable: true,
  value: {
    hostname: '',
  },
});

/**
 * Create "custom errors" to help emulate WebAuthn API errors
 */
type WebAuthnErrorName =
  'AbortError'
  | 'ConstraintError'
  | 'InvalidStateError'
  | 'NotAllowedError'
  | 'NotSupportedError'
  | 'SecurityError'
  | 'UnknownError';
function generateCustomError(name: WebAuthnErrorName): Error {
  const customError = new Error();
  customError.name = name;
  return customError;
}

Object.defineProperty(global, 'generateCustomError', { value: generateCustomError });
