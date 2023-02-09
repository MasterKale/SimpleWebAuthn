import { isValidDomain } from './isValidDomain';
import { WebAuthnError } from './structs';

/**
 * Attempt to intuit _why_ an error was raised after calling `navigator.credentials.get()`
 */
export function identifyAuthenticationError({
  error,
  options,
}: {
  error: Error;
  options: CredentialRequestOptions;
}): WebAuthnError | Error {
  const { publicKey } = options;

  if (!publicKey) {
    throw Error('options was missing required publicKey property');
  }

  if (error.name === 'AbortError') {
    if (options.signal === new AbortController().signal) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 16)
      return new WebAuthnError('Authentication ceremony was sent an abort signal', 'AbortError');
    }
  } else if (error.name === 'NotAllowedError') {
    /**
     * Pass the error directly through. Platforms are overloading this error beyond what the spec
     * defines and we don't want to overwrite potentially useful error messages.
     */
  } else if (error.name === 'SecurityError') {
    const effectiveDomain = window.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://www.w3.org/TR/webauthn-2/#sctn-discover-from-external-source (Step 5)
      return new WebAuthnError(`${window.location.hostname} is an invalid domain`, 'SecurityError');
    } else if (publicKey.rpId !== effectiveDomain) {
      // https://www.w3.org/TR/webauthn-2/#sctn-discover-from-external-source (Step 6)
      return new WebAuthnError(
        `The RP ID "${publicKey.rpId}" is invalid for this domain`,
        'SecurityError',
      );
    }
  } else if (error.name === 'UnknownError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion (Step 1)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion (Step 12)
    return new WebAuthnError(
      'The authenticator was unable to process the specified options, or could not create a new assertion signature',
      'UnknownError',
    );
  }

  return error;
}
