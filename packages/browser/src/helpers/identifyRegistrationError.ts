import { isValidDomain } from './isValidDomain';
import { WebAuthnError } from './structs';

/**
 * Attempt to intuit _why_ an error was raised after calling `navigator.credentials.create()`
 */
export function identifyRegistrationError({
  error,
  options,
}: {
  error: Error;
  options: CredentialCreationOptions;
}): WebAuthnError | Error {
  const { publicKey } = options;

  if (!publicKey) {
    throw Error('options was missing required publicKey property');
  }

  if (error.name === 'AbortError') {
    if (options.signal === new AbortController().signal) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 16)
      return new WebAuthnError('Registration ceremony was sent an abort signal', 'AbortError');
    }
  } else if (error.name === 'ConstraintError') {
    if (publicKey.authenticatorSelection?.requireResidentKey === true) {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 4)
      return new WebAuthnError(
        'Discoverable credentials were required but no available authenticator supported it',
        'ConstraintError',
      );
    } else if (publicKey.authenticatorSelection?.userVerification === 'required') {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 5)
      return new WebAuthnError(
        'User verification was required but no available authenticator supported it',
        'ConstraintError',
      );
    }
  } else if (error.name === 'InvalidStateError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 20)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 3)
    return new WebAuthnError('The authenticator was previously registered', 'InvalidStateError');
  } else if (error.name === 'NotAllowedError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 20)
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 21)
    return new WebAuthnError(
      'User clicked cancel, or the registration ceremony timed out',
      'NotAllowedError',
    );
  } else if (error.name === 'NotSupportedError') {
    const validPubKeyCredParams = publicKey.pubKeyCredParams.filter(
      param => param.type === 'public-key',
    );

    if (validPubKeyCredParams.length === 0) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 10)
      return new WebAuthnError(
        'No entry in pubKeyCredParams was of type "public-key"',
        'NotSupportedError',
      );
    }

    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 2)
    return new WebAuthnError(
      'No available authenticator supported any of the specified pubKeyCredParams algorithms',
      'NotSupportedError',
    );
  } else if (error.name === 'SecurityError') {
    const effectiveDomain = window.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 7)
      return new WebAuthnError(`${window.location.hostname} is an invalid domain`, 'SecurityError');
    } else if (publicKey.rp.id !== effectiveDomain) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 8)
      return new WebAuthnError(
        `The RP ID "${publicKey.rp.id}" is invalid for this domain`,
        'SecurityError',
      );
    }
  } else if (error.name === 'TypeError') {
    if (publicKey.user.id.byteLength < 1 || publicKey.user.id.byteLength > 64) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 5)
      return new WebAuthnError('User ID was not between 1 and 64 characters', 'TypeError');
    }
  } else if (error.name === 'UnknownError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 1)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 8)
    return new WebAuthnError(
      'The authenticator was unable to process the specified options, or could not create a new credential',
      'UnknownError',
    );
  }

  return error;
}
