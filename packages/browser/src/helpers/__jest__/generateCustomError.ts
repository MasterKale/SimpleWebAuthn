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
  | 'TypeError'
  | 'UnknownError';

export function generateCustomError(
  name: WebAuthnErrorName,
  message = '',
): Error {
  const customError = new Error();
  customError.name = name;
  customError.message = message;
  return customError;
}
