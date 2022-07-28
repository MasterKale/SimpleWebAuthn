/**
 * Create "custom errors" to help emulate WebAuthn API errors
 */
type WebAuthnErrorName =
  | 'AbortError'
  | 'ConstraintError'
  | 'InvalidStateError'
  | 'NotAllowedError'
  | 'NotSupportedError'
  | 'SecurityError'
  | 'UnknownError';

export function generateCustomError(name: WebAuthnErrorName): Error {
  const customError = new Error();
  customError.name = name;
  return customError;
}
